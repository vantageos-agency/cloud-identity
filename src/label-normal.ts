/**
 * @internal The package's one comparison form of an acting label: NFC,
 * lowercase, trim. Case and composition form fold; accents do not. Not exported
 * from the package root, so no consumer passes its own or depends on this one.
 */
export function normalizeLabel(label: string): string {
  return label.normalize("NFC").toLowerCase().trim();
}
