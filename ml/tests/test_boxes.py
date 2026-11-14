from cipherframe_ml.boxes import Holder, pad_box, scale_box


def test_pad_adds_25_percent_each_side():
    assert pad_box((100, 100, 40, 80), 640, 480) == (90, 80, 60, 120)


def test_pad_clamps_to_frame():
    assert pad_box((0, 0, 40, 40), 100, 100) == (0, 0, 50, 50)
    x, y, w, h = pad_box((90, 90, 40, 40), 100, 100)
    assert (x + w, y + h) == (100, 100)


def test_pad_box_outside_frame_is_empty():
    assert pad_box((500, 500, 10, 10), 100, 100)[2:] == (0, 0)


def test_scale_back():
    assert scale_box((10, 20, 30, 40), 2.0) == (20, 40, 60, 80)


def test_hold_keeps_box_for_one_second_then_drops():
    holder = Holder(fps=10)  # 10 frames
    box = (1, 2, 3, 4)
    assert holder.update([box]) == [box]
    for _ in range(10):
        assert holder.update([]) == [box]
    assert holder.update([]) == []


def test_new_detection_replaces_and_resets_hold():
    holder = Holder(fps=2)  # 2 frames
    holder.update([(1, 1, 1, 1)])
    holder.update([])
    assert holder.update([(5, 5, 5, 5)]) == [(5, 5, 5, 5)]
    assert holder.update([]) == [(5, 5, 5, 5)]
    assert holder.update([]) == [(5, 5, 5, 5)]
    assert holder.update([]) == []


def test_every_face_is_kept():
    holder = Holder(fps=10)
    boxes = [(1, 1, 5, 5), (50, 50, 5, 5)]
    assert holder.update(boxes) == boxes
    assert holder.update([]) == boxes
