export default {
  async fetch(request, env) {
    return new Response("Worker is running!");
  }
}
