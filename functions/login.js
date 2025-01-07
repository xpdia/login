async function generateJWTToken() {
  const jwtKey = "UNdfDGCc10ItG8WasIPmQLjdAY30tP88RT6/viWpKg7UnwbG4/lQ2MvVMvFd6MzvPzgrznIwPi5Jr/QhC/8K9Q==";
  const header = { alg: "HS256", typ: "JWT" };
  const currentTime = Math.floor(Date.now() / 1000);
  const expirationTime = currentTime + 30;
  const payload = { exp: expirationTime };

  // Base64 encoding function (compatible with Cloudflare)
  const encodeBase64 = (data) => 
    btoa(String.fromCharCode(...new Uint8Array(data)));

  const encodeToString = (input) => 
    btoa(JSON.stringify(input));

  const encodedHeader = encodeToString(header);
  const encodedPayload = encodeToString(payload);

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(jwtKey),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const data = new TextEncoder().encode(encodedHeader + "." + encodedPayload);
  const signature = await crypto.subtle.sign("HMAC", key, data);

  const signatureBase64 = encodeBase64(signature);

  const jwtToken = `${encodedHeader}.${encodedPayload}.${signatureBase64}`;
  return jwtToken;
}

async function authenticateUser(username, password) {
  // Simple authentication logic
  return username === "rzwn" && password === "rzwn121";
}

export async function onRequest(context) {
  try {
    const formdata = await context.request.formData();
    const username = formdata.get("username");
    const password = formdata.get("password");

    if (!username || !password) {
      return new Response("Invalid request", { status: 400 });
    }

    const isAuthenticated = await authenticateUser(username, password);

    if (isAuthenticated) {
      const jwtToken = await generateJWTToken();
      const cookie = `jwtToken=${jwtToken}; HttpOnly; Secure; SameSite=Strict`;

      const headers = {
        "Set-Cookie": cookie,
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
        "Location": "/admin"
      };

      return new Response("true", { headers, status: 200 });
    } else {
      return new Response("Unauthorized", { status: 401 });
    }
  } catch (error) {
    return new Response("Server error", { status: 500 });
  }
}
