# GIIA MVP 1.0 Release Verification

## Frozen Release Identity

Tag:

    giia-mvp-1.0.0

Commit:

    3c7c8385bccb25c084ee80c3b45644676ba876f5

## Required Verification

Run:

    git checkout giia-mvp-1.0.0
    git describe --tags --exact-match HEAD
    git rev-parse HEAD

Expected:

    giia-mvp-1.0.0

and:

    3c7c8385bccb25c084ee80c3b45644676ba876f5

## Build Verification

Run:

    npm install
    npm run build

Expected:

    successful TypeScript compilation

## Test Verification

Run:

    npm test

Expected:

    477 tests
    477 pass
    0 fail
    0 cancelled
    0 skipped
    0 todo

## Integrity Principle

Reviewers should record the exact commit tested.

Security findings should identify the exact commit and environment in which
they were reproduced.

Do not report results from a modified working tree as results for the frozen
MVP release.

## Reproduction Rule

The frozen tag is the reference artifact.

Reviewers may create separate branches for experimentation, patches,
instrumentation, fuzzing, or proof-of-concept work.

The frozen release itself should remain unchanged.

## Verification Result

A reviewer should be able to independently establish:

1. The release tag resolves to the documented commit.
2. The documented commit builds successfully.
3. The documented commit reproduces the documented test baseline.
4. The security review is being performed against the identified artifact.

Passing these checks establishes reproducibility of the baseline. It does
not establish absence of vulnerabilities.
