const encoded = "Y29uc29sZS5sb2coIkZBS0UgTUFMSUNJT1VTIElOU1RBTEwgU0NSSVBUIFJBTiIpOw==";

const decoded = Buffer.from(encoded, "base64").toString("utf8");

eval(decoded);