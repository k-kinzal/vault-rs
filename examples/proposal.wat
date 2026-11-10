;; Echo the already-authorized IssueSpec. No imports, IO, or credential access.
(module
  (memory (export "memory") 1 1)
  (func (export "propose") (param i32 i32) (result i64)
    local.get 1
    i64.extend_i32_u))
