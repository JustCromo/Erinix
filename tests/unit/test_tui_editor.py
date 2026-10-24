from erinix.tui.editor import MAX_LEN, LineEditor


def typed(text, cursor=None):
    e = LineEditor()
    e.insert(text)
    if cursor is not None:
        e.cursor = cursor
    return e


def test_insert_in_the_middle_and_backspace_delete():
    e = typed("helo", 3)
    e.insert("l")
    assert (e.text, e.cursor) == ("hello", 4)
    e.backspace()
    e.delete()
    assert e.text == "hel" and e.cursor == 3
    e.home()
    e.backspace()
    assert e.text == "hel"


def test_control_characters_are_filtered_and_length_capped():
    e = LineEditor()
    e.insert("a\x1b[31m\nb\x00")
    assert e.text == "a[31mb"
    e.kill_line()
    e.insert("x" * (MAX_LEN + 50))
    assert len(e.text) == MAX_LEN


def test_movements_and_words():
    e = typed("rules validate  /etc")
    e.word_left()
    assert e.cursor == 16
    e.word_left()
    assert e.cursor == 6
    e.word_right()
    assert e.cursor == 14
    e.home()
    e.right()
    e.left()
    e.end()
    assert e.cursor == len(e.text)


def test_kill_and_delete_word():
    e = typed("rules validate /etc")
    e.delete_word_back()
    assert e.text == "rules validate "
    e.home()
    e.right()
    e.kill_to_end()
    assert e.text == "r"
    e.kill_line()
    assert (e.text, e.cursor) == ("", 0)


def test_history_navigation_keeps_draft():
    e = LineEditor(["uno", "due"])
    e.insert("bozza")
    e.history_prev()
    assert e.text == "due"
    e.history_prev()
    assert e.text == "uno"
    e.history_prev()
    assert e.text == "uno"
    e.history_next()
    e.history_next()
    assert e.text == "bozza"
    e.history_next()
    assert e.text == "bozza"


def test_submit_records_history_without_duplicates_or_blanks():
    e = LineEditor(["help"])
    e.insert("help")
    assert e.submit() == "help" and e.history == ["help"] and e.text == ""
    e.insert("   ")
    e.submit()
    e.insert("doctor")
    e.submit()
    assert e.history == ["help", "doctor"]
    e.forget_last("doctor")
    assert e.history == ["help"]
    e.forget_last("altro")
    assert e.history == ["help"]
