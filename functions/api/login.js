export async function onRequestPost(context) {
  const { request, env } = context
  const form = await request.formData()
  const code = (form.get('pw') || '').toString().trim()

  if (code === env.ACCESS_CODE) {
    const headers = new Headers({ 'Location': '/' })
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
