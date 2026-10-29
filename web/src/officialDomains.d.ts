declare module 'virtual:official-domains' {
  /** Brand name (as the API reports it) -> its official registrable domains. */
  const domains: Record<string, string[]>
  export default domains
}
