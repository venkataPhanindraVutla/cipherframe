"""The shared vectors in spec/jobs/vectors must validate (or not) against their schemas."""

import json

import pytest

from conftest import SPEC, validator

SCHEMAS = {
    "envelope-": "envelope.schema.json",
    "result-": "result.schema.json",
    "payload-mask-faces-": "kinds/media.mask_faces.payload.schema.json",
    "output-mask-faces-": "kinds/media.mask_faces.output.schema.json",
}


def cases():
    for kind in ("valid", "invalid"):
        for f in sorted((SPEC / "vectors" / kind).glob("*.json")):
            prefix = next(p for p in SCHEMAS if f.name.startswith(p))
            yield pytest.param(kind == "valid", SCHEMAS[prefix], f, id=f"{kind}/{f.name}")


@pytest.mark.parametrize(("is_valid", "schema", "path"), cases())
def test_vector(is_valid, schema, path):
    errors = list(validator(schema).iter_errors(json.loads(path.read_text())))
    assert (not errors) == is_valid, errors
