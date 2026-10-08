import test from 'node:test';
import assert from 'node:assert/strict';

import { canonicalHash, canonicalize } from '../../src/core/canonical.js';
import { constantTimeEqual, sha256 } from '../../src/core/security.js';

test('canonical serialization is independent of object key order', () => {
  const a = canonicalize({ z: 1, a: 2 });
  const b = canonicalize({ a: 2, z: 1 });

  assert.equal(a, b);
  assert.equal(
    canonicalHash({ z: 1, a: 2 }),
    canonicalHash({ a: 2, z: 1 }),
  );
});

test('SHA-256 is deterministic', () => {
  assert.equal(
    sha256('GIIA'),
    '5527449ff1f86d74c48f445d5a5f0e379bf33a7ba02e6ba41379cdc8d22f81d1',
  );
});

test('constant-time comparison handles equal and unequal values', () => {
  assert.equal(constantTimeEqual('abc', 'abc'), true);
  assert.equal(constantTimeEqual('abc', 'abd'), false);
  assert.equal(constantTimeEqual('abc', 'abcd'), false);
});
