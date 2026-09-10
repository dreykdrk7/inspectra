import { readdirSync, statSync } from "node:fs";
import { join } from "node:path";

// The archive-snapshot flow adds a lazily loaded form; retain a small, explicit
// allowance for its lightweight launch control while continuing to guard the
// initial dashboard bundle.
const MAX_INITIAL_BUNDLE_BYTES = 322 * 1024;
const assetsDirectory = join("dist", "assets");
const initialBundles = readdirSync(assetsDirectory).filter((entry) => /^index-[\w-]+\.js$/.test(entry));

if (initialBundles.length !== 1) {
  throw new Error(`Expected exactly one initial JavaScript bundle in ${assetsDirectory}; found ${initialBundles.length}.`);
}

const initialBundle = join(assetsDirectory, initialBundles[0]);
const initialBundleBytes = statSync(initialBundle).size;

if (initialBundleBytes > MAX_INITIAL_BUNDLE_BYTES) {
  throw new Error(
    `Initial bundle is ${(initialBundleBytes / 1024).toFixed(1)} KiB; budget is ${(MAX_INITIAL_BUNDLE_BYTES / 1024).toFixed(0)} KiB.`
  );
}

console.log(
  `Initial bundle budget passed: ${(initialBundleBytes / 1024).toFixed(1)} KiB / ${(MAX_INITIAL_BUNDLE_BYTES / 1024).toFixed(0)} KiB (${initialBundle}).`
);
