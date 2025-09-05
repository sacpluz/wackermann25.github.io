// Cloudflare Pages Functions middleware for all routes
export async function onRequest(context) {
  const { request, env, next } = context
  const url = new URL(request.url)
  const isLoginRoute = url.pathname === '/login' || url.pathname === '/api/login' || url.pathname === '/logout'
  const isAsset = /\.(png|jpg|jpeg|gif|svg|webp|ico|css|js|map|woff2?|ttf|txt)$/i.test(url.pathname)

  // allow assets and login routes without auth
  if (isLoginRoute || isAsset) {
    // handle POST /api/login
    if (url.pathname === '/api/login' && request.method === 'POST') {
      const form = await request.formData()
      const code = (form.get('pw') || '').toString().trim()
      const correct = code === env.ACCESS_CODE
      // small constant-time compare alternative:
      // const correct = timingSafeEqual(code, env.ACCESS_CODE)

      if (correct) {
        // secure cookie
        const headers = new Headers({ 'Location': '/' })
        // cookie is httpOnly, secure, sameSite strict
        headers.append(
          'Set-Cookie',
          `wackermann_auth=1; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${60 * 60 * 8}`
        )
        return new Response(null, { status: 302, headers })
      } else {
        const headers = new Headers({ 'Location': '/login?err=1' })
        return new Response(null, { status: 302, headers })
      }
    }

    // handle GET /logout
    if (url.pathname === '/logout') {
      const headers = new Headers({ 'Location': '/login' })
      headers.append(
        'Set-Cookie',
        'wackermann_auth=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0'
      )
      return new Response(null, { status: 302, headers })
    }

    return next()
  }

  // check cookie for protected routes
  const cookie = request.headers.get('Cookie') || ''
  const authed = /(?:^|;\s*)wackermann_auth=1(?:;|$)/.test(cookie)

  if (authed) return next()

  // not authed → redirect to login
  const headers = new Headers({ 'Location': '/login' })
  return new Response(null, { status: 302, headers })
}

// Optional timing-safe compare if du hashst den Code in ENV
function timingSafeEqual(a, b) {
  const enc = new TextEncoder()
  const ab = enc.encode(a)
  const bb = enc.encode(b)
  if (ab.length !== bb.length) return false
  let out = 0
  for (let i = 0; i < ab.length; i++) out |= ab[i] ^ bb[i]
  return out === 0
}
