const DEFAULT_KEY = [48, 174, 137, 138, 134, 125, 45, 5, 20, 156, 233, 94, 133, 192, 55, 42, 196, 197, 155, 237, 108, 44, 168, 232, 89, 152, 138, 44, 21, 60, 197, 150];
function getKey(customKeyInput) {
  if (!customKeyInput) return new Uint8Array(DEFAULT_KEY);
  const keyArray = customKeyInput.split(",").map((s) => parseInt(s.trim()));
  if (keyArray.length !== 32) {
    throw new Error("Key must be exactly 32 bytes");
  }
  if (keyArray.some((b) => isNaN(b) || b < 0 || b > 255)) {
    throw new Error("All key bytes must be integers between 0 and 255");
  }
  return new Uint8Array(keyArray);
}

function formatAndSort(input) {
  try {
    const parsed = JSON.parse(input);

    try {
      if (Array.isArray(parsed?.events)) parsed.events = parsed.events.sort((a, b) => a[0] - b[0]);
    } catch {}

    return JSON.stringify(parsed, null, 2);
  } catch (e) {
    console.log(e);
    // If it's not valid JSON, return the input as-is
    return input;
  }
}

async function AESGCMencryptData(plaintext, config) {
  const key = getKey(config.key);
  if (!key) return;

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["encrypt"]);

  const encoded = new TextEncoder().encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, cryptoKey, encoded);

  const encryptedArray = new Uint8Array(encrypted);
  const result = new Uint8Array(encryptedArray.length + iv.length + 1);
  result.set(encryptedArray, 0);
  result.set(iv, encryptedArray.length);
  result[result.length - 1] = 0;

  const base64Result = btoa(String.fromCharCode(...result));
  return base64Result;
}

async function AESGCMdecryptData(encryptedInput, config) {
  const key = getKey(config.key);
  const encryptedData = Uint8Array.from(atob(encryptedInput), (c) => c.charCodeAt(0));
  const iv = encryptedData.slice(-13, -1);
  const tag = encryptedData.slice(-29, -13);
  const ciphertext = encryptedData.slice(0, -29);
  const combinedData = new Uint8Array(ciphertext.length + tag.length);
  combinedData.set(ciphertext, 0);
  combinedData.set(tag, ciphertext.length);
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, cryptoKey, combinedData);
  const decryptedText = new TextDecoder().decode(decrypted);
  return config.format ? formatAndSort(decryptedText) : decryptedText;
}

export default { AESGCMdecryptData, AESGCMencryptData };
