"""A believable live session, played in real time: normal traffic with a staged attack in the middle.

Nothing real is touched. Events are built by the same helpers as the replay scenarios (web lines go
through the production Caddy parser, SSH lines through the production sshd parser), re-stamped with
the current time as they are fed, so the engine and the dashboard behave exactly as they would live.
"""

from __future__ import annotations

import dataclasses
import random
import time
from typing import Callable

from erinix.core.events import Event
from erinix.demo import scenarios as sc

# (start second, speed-up factor) of every staged part of the story.
STAGES = (("web", 8.0, 1.6), ("ssh", 36.0, 2.0), ("revshell", 50.0, 1.8), ("shadow", 72.0, 1.0))
STORY_SECONDS = 76.0

_PAGES = ("/", "/static/app.js", "/static/style.css", "/products?sort=price", "/products?id=3", "/about", "/search?q=milk",
          "/products?id=12", "/cart", "/static/logo.png", "/products?category=dairy")
_VISITORS = ("192.168.50.20", "192.168.50.21", "192.168.50.22", "192.168.50.23")


def story() -> list[tuple[float, Event]]:
    """The staged attack as (seconds from the start, event). Fresh events on every call."""
    parts = {"web": sc._web, "ssh": sc._ssh_log, "revshell": sc._revshell, "shadow": sc._shadow}
    timeline = []
    for name, start, scale in STAGES:
        for event in parts[name]():
            timeline.append((start + event.mono_ns / sc.SEC * scale, event))
    return sorted(timeline, key=lambda item: item[0])


def noise(rng: random.Random, counter: int) -> Event:
    """Ordinary, harmless activity: browsing, an administrator's key login, a scheduled job."""
    roll = rng.random()
    if roll < 0.78:
        return sc._caddy(rng.choice(_VISITORS), "GET", rng.choice(_PAGES), 200, 0)
    if roll < 0.90:
        return sc._caddy(rng.choice(_VISITORS), "GET", rng.choice(("/favicon.ico", "/robots.txt")), 404, 0)
    if roll < 0.96:
        return sc._ssh(f"Nov 12 10:00:{counter % 60:02d} pi sshd-session[812]: Accepted publickey for ivan from 192.168.50.10 port 5555 ssh2", 0)
    cron = sc._p(3000 + counter % 900, 100 + counter, 1, 0, "/usr/sbin/cron", uid=0)
    return sc._exec(cron, 0)


def stamp(event: Event) -> Event:
    return dataclasses.replace(event, mono_ns=time.monotonic_ns(), wall_ns=time.time_ns())


def run(feed: Callable[[Event], object], *, rng: random.Random | None = None, speed: float = 1.0, duration: float | None = None,
        clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
        stop: Callable[[], bool] = lambda: False, tick: Callable[[], None] | None = None) -> dict:
    """Feed the story and the background traffic as time passes. Stops after `duration` seconds (None: until `stop()`)."""
    if not 0.2 <= speed <= 10:
        raise ValueError("speed must be between 0.2 and 10")
    rng = rng or random.Random()
    script = story()
    start = clock()
    index, counter, fed, next_noise, last_tick = 0, 0, 0, start + 0.4, start
    while not stop():
        now = clock()
        elapsed = (now - start) * speed
        due: list[Event] = []
        while index < len(script) and script[index][0] <= elapsed:
            due.append(script[index][1])
            index += 1
        if now >= next_noise:
            counter += 1
            due.append(noise(rng, counter))
            next_noise = now + rng.uniform(0.35, 1.2) / speed
        for event in due:
            feed(stamp(event))
            fed += 1
        if tick is not None and now - last_tick >= 1.0:
            last_tick = now
            tick()
        if duration is not None and now - start >= duration:
            break
        sleep(0.05)
    return {"events": fed, "story_finished": index >= len(script)}
