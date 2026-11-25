import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples_test"

import pytest  # noqa: E402

from scripts.generate_samples import generate  # noqa: E402


@pytest.fixture(scope="session")
def sample_data():
    """整套测试共享一份真实生成的 PKI 样例。"""
    generate(SAMPLES)
    return json.loads((SAMPLES / "sample.json").read_text(encoding="utf-8"))


@pytest.fixture()
def rows(sample_data):
    import copy

    return copy.deepcopy(sample_data)
