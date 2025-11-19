function parseBinary(hexDump, options) {
  let arr = hexDump
    .split("\n")
    .map((line) => {
      // Extract hex bytes (columns between offset and ASCII)
      const match = line.match(/^[0-9a-f]+\s+((?:[0-9a-f]{2}\s+)+)/i);
      return match ? match[1].trim().split(/\s+/) : [];
    })
    .flat();

if (options.zerox) arr = arr.map(e => `0x${e}`)

  if (options.commas) return "[" + arr.join(", ") + "]";
  else return arr.join(" ");
}

export default { parseBinary };
