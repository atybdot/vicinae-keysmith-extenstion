export function getBrandIcon(issuer: string, account: string): string | null {
  const text = `${issuer} ${account}`.toLowerCase();
  if (/\b(instagram|insta)\b/.test(text)) return "brands/instagram.svg";
  if (/\bgoogle\b/.test(text)) return "brands/google.svg";
  if (/\bmega\b/.test(text)) return "brands/mega.svg";
  if (/\bbitwarden\b/.test(text)) return "brands/bitwarden.svg";
  if (/\bgithub\b/.test(text)) return "brands/github.svg";
  if (/\binance\b/.test(text)) return "brands/binance.svg";
  if (/\bvercel\b/.test(text)) return "brands/vercel.svg";
  if (/\bautodesk\b/.test(text)) return "brands/autodesk.svg";
  if (/\bcoinbase\b/.test(text)) return "brands/coinbase.svg";
  if (/\bnamecheap\b/.test(text)) return "brands/namecheap.svg";
  if (/\btutanota\b|\btuta\b/.test(text)) return "brands/tutanota.svg";
  if (/\bwazirx\b/.test(text)) return "brands/wazirx.svg";
  if (/\bdodo\b/.test(text)) return "brands/dodopayments.svg";
  if (/\bx\.com\b|\btwitter\b/.test(text)) return "brands/x.svg";
  return null;
}
