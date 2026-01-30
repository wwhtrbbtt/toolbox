import js_beautify from "js-beautify";
import deobfuscate from "./deobfuscate";
import ToolType from "./types";
import tlsConverter from "./tlsConverter";
import aes from "./aes";
import charles from "./charles";

const encodeAuthKey = (key) =>
  key
    .split("")
    .map((x) => String.fromCharCode(x.charCodeAt() + 3))
    .join("");

const headerToCode = (i) =>
  JSON.stringify(
    i
      .split("\n")
      .map((e) => e.split(": "))
      .filter((e) => e.length === 2 && !e[0].startsWith(":"))
      .reduce((a, v) => ({ ...a, [v[0]]: v[1] }), new Map()),
    null,
    "\t"
  );

const tools = [
  {
    name: "b64_encode",
    title: "Base64 encoder",
    subtitle: "A simple ASCII to Base64 encoding utility",
    func: (i) => btoa(i),
    similar: ["b64_decode"],
    placeholder: "Hello, world!",
    type: ToolType.GENERAL,
  },
  {
    name: "b64_decode",
    title: "Base64 decoder",
    subtitle: "A simple Base64 to text decoding utility",
    func: (i) => atob(i),
    similar: ["b64_encode"],
    placeholder: "SGVsbG8sIHdvcmxkIQ==",
    type: ToolType.GENERAL,
  },
  {
    name: "url_encoder",
    title: "URL encoder",
    subtitle: "A simple utility to URL-encode a string",
    func: encodeURIComponent,
    similar: ["url_decoder"],
    placeholder: "https://tools.peet.ws",
    type: ToolType.GENERAL,
  },
  {
    name: "url_decoder",
    title: "URL decoder",
    subtitle: "A simple decoder for URL encoded strings",
    func: decodeURIComponent,
    similar: ["url_encoder"],
    placeholder: "https%3A%2F%2Ftools.peet.ws%2F",
    type: ToolType.GENERAL,
  },
  {
    name: "rot13",
    title: "Rot13 decoder",
    subtitle: "An utility for encoding/decoding Rot13 encrypted text",
    func: (i) => i.replace(/[a-z]/gi, (letter) => String.fromCharCode(letter.charCodeAt(0) + (letter.toLowerCase() <= "m" ? 13 : -13))),
    placeholder: "Uryyb, jbeyq!",
    type: ToolType.GENERAL,
  },
  {
    name: "json_formatter",
    title: "JSON formatter",
    subtitle: "An utility for formatting/verifiying ugly JSON",
    func: (i) => JSON.stringify(JSON.parse(i), null, "\t"),
    similar: ["js_formatter"],
    placeholder: `{"hello": {"w": "orld", "!": ""}}`,
    type: ToolType.GENERAL,
  },
  {
    name: "js_formatter",
    title: "JavaScript formatter",
    subtitle: "An utility for formatting/verifiying ugly JavaScript",
    func: (i) => js_beautify(i, { indent_size: 2, space_in_empty_paren: true }),
    similar: ["json_formatter", "js_deobfuscator"],
    placeholder: `console.log((() => {return (() => {return atob("SGVsbG8sIHdvcmxkIQ==")})()})())`,
    type: ToolType.GENERAL,
  },
  {
    name: "uuid_analyzer",
    title: "UUID analyzer",
    subtitle: "An utility for getting all information out of an UUID (timestamp + version)",
    similar: ["jwt_decoder"],
    func: (i) => {
      if (i.length !== 36) return "Invalid UUID";
      const blocks = i.split("-");
      if (blocks.length !== 5) return "Invalid UUID";
      const version = blocks[2][0];

      return `UUID: ${i}\n\nVersion: ${version}\nTimestamp: WIP`;
    },
    placeholder: "626245c9-0683-457a-bb33-7ffd8de051d8",
    type: ToolType.GENERAL,
  },
  {
    name: "jwt_decoder",
    title: "JWT decoder",
    subtitle: "An utility for decoding a JSON Web Token (JWT)",
    similar: ["uuid_analyzer"],
    func: (i) => {
      const meta = JSON.stringify(JSON.parse(atob(i.split(".")[0])), null, "\t");
      const main = JSON.stringify(JSON.parse(atob(i.split(".")[1])), null, "\t");
      return `Meta information:\n${meta}\n\nEncoded data:\n${main}`;
    },
    placeholder:
      "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJPbmxpbmUgSldUIEJ1aWxkZXIiLCJpYXQiOjE3MDMyNDA3ODUsImV4cCI6MTczNDc3Njc4NSwiYXVkIjoid3d3LmV4YW1wbGUuY29tIiwic3ViIjoianJvY2tldEBleGFtcGxlLmNvbSIsIkdpdmVuTmFtZSI6IkpvaG5ueSIsIlN1cm5hbWUiOiJSb2NrZXQiLCJFbWFpbCI6Impyb2NrZXRAZXhhbXBsZS5jb20iLCJSb2xlIjpbIk1hbmFnZXIiLCJQcm9qZWN0IEFkbWluaXN0cmF0b3IiXX0.fGnTY8mIWRwmxWRDaCfmnXyCWFVXShoCmn80watsb_g",
    type: ToolType.GENERAL,
  },
  {
    name: "header_formatter",
    title: "Header to code",
    subtitle: "An utility for converting raw HTTP headers (for example from charles) to a JSON object",
    similar: ["uuid_analyzer", "jwt_decoder", "js_formatter", "header_formatter_fhttp"],
    func: headerToCode,
    placeholder: `GET  /tools/header_formatter HTTP/1.1\nHost: tools.peet.ws\nHello: World!`,
    type: ToolType.GENERAL,
  },
  {
    name: "charles_binary_parser",
    title: "Charles binary parser",
    subtitle: "An utility for converting the 'binary' response data from charles proxy to actual binary",
    similar: ["uuid_analyzer", "jwt_decoder", "js_formatter", "header_formatter_fhttp"],
    func: charles.parseBinary,
    placeholder: `00000000  7e d1 5d 7e 7e f3 d8 c3 16 20 f3 e2 fa 4d 8d 6b   ~ ]~~        M k
00000010  e3 77 0d 2c 4a bc d0 7f 76 7b 3c b9 66 a5 5c 4f    w ,J  v{< f \O!`,
    type: ToolType.GENERAL,
    config: [
      { title: "Seperate with commas", name: "commas", val: true },
      { title: "Use 0xXX syntax", name: "zerox", val: true },
    ],
  },

  // == ANTBOT RELATED ==
  {
    name: "header_formatter_fhttp",
    title: "Header to code (fhttp)",
    subtitle: "An utility for converting raw HTTP headers (for example from charles) to valid Golang code (fhttp library)",
    similar: ["header_formatter", "uuid_analyzer", "jwt_decoder", "js_formatter", "tls_converter"],
    func: (i) => {
      const h = JSON.parse(headerToCode(i));

      const order = Object.keys(h)
        .map((k) => `"${k}"`)
        .join(", ");

      const headers = Object.entries(h)
        .map(([k, v]) => `\t"${k}":\t\t{"${v.replaceAll('"', '\\"')}"},\n`)
        .filter((a) => !a.toLowerCase().includes(`"cookie":`))
        .join("");

      return `req.Header = http.Header{\n${headers}\thttp.HeaderOrderKey: { ${order} },\n}`;
    },
    placeholder: `GET  /tools/header_formatter_fhttp HTTP/1.1\nHost: tools.peet.ws\nHello: World!`,
    type: ToolType.GENERAL,
  },
  {
    name: "js_deobfuscator",
    title: "JavaScript deobfuscator",
    subtitle: "An utility that converts ugly JavaScript into more readable code",
    similar: ["js_formatter", "json_formatter"],
    func: deobfuscate,
    config: [
      { title: "Replace hex", name: "replace_hex", val: true },
      { title: "Remove unused", name: "delete_unused", val: true },
      { title: "Beautify", name: "beautify", val: true },
      { title: "Rename", name: "rename", val: false },
    ],
    placeholder: `const a = 0x0;\nconst b = 0x125;\nconst s = " ";\nconsole.log("Hell"+a*b+s+"w"+(b-b)+"rld");`,
    type: ToolType.ANTIBOT,
  },
  {
    name: "aes-gcm-encrypt",
    title: "AES-GCM Encrypt",
    subtitle: "An utility that can encrypt using AES-GCM with a custom key. Used by some antibots, which like to sue you if you mention them.",
    similar: ["aes-gcm-decrypt"],
    func: aes.AESGCMencryptData,
    config: [{ title: "Decryption key", name: "key", val: "48, 174, 137, 138, 134, 125, 45, 5, 20, 156, 233, 94, 133, 192, 55, 42,196, 197, 155, 237, 108, 44, 168, 232, 89, 152, 138, 44, 21, 60, 197, 150" }],
    placeholder: `Input data to get started`,
    type: ToolType.ANTIBOT,
  },
  {
    name: "aes-gcm-decrypt",
    title: "AES-GCM Decrypt",
    subtitle: "An utility that can decrypt using AES-GCM with a custom key. Used by some antibots, which like to sue you if you mention them.",
    similar: ["aes-gcm-encrypt"],
    func: aes.AESGCMdecryptData,
    config: [
      { title: "Encryption key", name: "key", val: "48, 174, 137, 138, 134, 125, 45, 5, 20, 156, 233, 94, 133, 192, 55, 42,196, 197, 155, 237, 108, 44, 168, 232, 89, 152, 138, 44, 21, 60, 197, 150" },
      { title: "Format & Sort", name: "format", val: false },
    ],
    placeholder: `Input data to get started`,
    type: ToolType.ANTIBOT,
  },
  {
    name: "tls_converter",
    title: "JSON to uTLS",
    subtitle: "Convert JSON responses from tls.peet.ws/api/all to client profiles for github.com/bogdanfinn/tls-client",
    similar: ["header_formatter_fhttp"],
    type: ToolType.ANTIBOT,
    func: (rawPayload, cnfg = {}) => {
      try {
        const j = JSON.parse(rawPayload);
        return tlsConverter(j);
      } catch (e) {
        return e.message;
      }
    },
  },

  // == EXTERNAL ==
  {
    title: "decode.antibot.to",
    subtitle: "Collection of open-source tools and ressources to help reverse-engineering",
    link: "https://decode.antibot.to/",
    type: ToolType.EXTERNAL,
  },
  {
    title: "RegExr",
    subtitle: "RegExr is an online tool to learn, build, & test Regular Expressions (RegEx / RegExp)",
    link: "https://regexr.com/",
    type: ToolType.EXTERNAL,
  },
  {
    title: "CurlConverter",
    subtitle: "Convert cURL commands to code in different languages",
    link: "https://curlconverter.com/",
    type: ToolType.EXTERNAL,
    similar: ["header_formatter"],
  },
  {
    title: "TrackMe: Request fingerprinting demo",
    subtitle: "tls.peet.ws: find out what fingerprints your browser leaves on the web",
    link: "https://tls.peet.ws",
    type: ToolType.EXTERNAL,
  },
  {
    title: "CyberChef",
    subtitle: "The Cyber Swiss Army Knife, allows you to combine ~300 text operations",
    link: "https://gchq.github.io/CyberChef/",
    type: ToolType.EXTERNAL,
  },
  {
    title: "TLS-Client",
    subtitle: "The best TLS client that serves all your needs",
    link: "https://github.com/bogdanfinn/tls-client",
    type: ToolType.EXTERNAL,
  },
  {
    title: "Text difference checker",
    subtitle: "Git-style diff checker",
    link: "https://platform.text.com/tools/diff-checker",
    type: ToolType.EXTERNAL,
  },

  // == HIDDEN ==
  {
    name: "luca-encode",
    title: "Luca Encode",
    subtitle: "Auth key encoder",
    func: encodeAuthKey,
    placeholder: "Enter key to encode",
    type: ToolType.HIDDEN,
  },
];

export default () => {
  return tools;
};
