# Change: Simplify SecureCookie API

## Why
The generic `SecureCookie[T]` introduced unnecessary complexity for the simple use case of encoding and decoding a single cookie.

## What Changes
The `SecureCookie` interface will be updated to:
- Use `any` for `Encode` instead of `T`.
- Pass a pointer to destination value to `Decode` instead of creating a new value of that type and returning the unmarshaled value.
- Explicitly require `Name()` method to access the cookie name.

## Risks
- Losing compile-time type safety for encoded values.
