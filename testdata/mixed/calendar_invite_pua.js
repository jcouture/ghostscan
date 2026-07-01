const hidden = "";
const decoded = Buffer.from(hidden, "utf8");
eval(decoded.toString());
