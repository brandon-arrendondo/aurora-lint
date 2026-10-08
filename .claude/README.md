# Commit command deny rules

`settings.json` denies ordinary hook-bypassing commits, including `-nm` and
`-snm`. Patterns match command text: a message such as `git commit -m "fix -n
flag"` may also be denied. Use a message file for that legitimate case.
These patterns do not interpret every possible flag bundle or arbitrary
program that invokes Git. CI checks commit messages and reruns hooks.
