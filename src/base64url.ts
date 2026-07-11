/**
 * `base64url` interop shim.
 *
 * The package ships ESM-style type declarations (`export default base64url`)
 * over a CommonJS runtime. Under NodeNext module resolution the default import
 * is typed as the module namespace object rather than the callable `Base64Url`,
 * so member access (`base64url.encode(...)`) fails to type-check. At runtime
 * `esModuleInterop` already yields the callable, so this is a type-only
 * correction, centralized here rather than repeated at every call site.
 */
import base64urlDefault, { type Base64Url } from "base64url";

const base64url = base64urlDefault as unknown as Base64Url;

export default base64url;
