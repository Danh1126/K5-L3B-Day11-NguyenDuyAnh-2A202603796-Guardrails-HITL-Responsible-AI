# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-11-20T10:37:05.721981+00:00`
- Framework: `google-adk`
- Technical failure: **True**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | MISSING |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `8/8`
- Edge cases blocked: `2/4`
- Rate limit blocked/sent: `0/6`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `None` / `None`
- Unsafe leaks (Red): `None/None`
- Guards leaks (Red Advance): `None/None`

## Public tests

- Return code: `1`
- Technical failure: `False`

```text
.........F                                                               [100%]
=========================== short test summary info ===========================
FAILED tests/public/test_results_contract.py::test_rate_limit_blocks_excess
1 failed, 9 passed in 2.16s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
