export default function About() {
  return (
    <div className="prose max-w-3xl space-y-4 dark:prose-invert">
      <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">About QRGUARD</h1>
      <p>
        QRGUARD helps you spot scams in links, QR codes, UPI IDs, messages and screenshots. It was built as a
        final-year Computer Engineering project. It looks for known scam tricks, reads text in images and asks scam
        databases whether they know the link.
      </p>
      <h2 className="text-xl font-semibold">How it decides</h2>
      <ul className="list-disc space-y-1 pl-6">
        <li>Every result lists the warning signs it found and how many points each one added to the score.</li>
        <li>The result (safe, suspicious or dangerous) comes only from the score. Whether a scam database confirmed it is shown separately.</li>
        <li>"Not on a scam list" never makes something look safer: new scams are often on no list yet.</li>
      </ul>
      <h2 className="text-xl font-semibold">Privacy</h2>
      <ul className="list-disc space-y-1 pl-6">
        <li>We never open the link on your phone. Our server only follows short links to see where they really go.</li>
        <li>Your messages, screenshots and QR codes are not stored.</li>
        <li>QR codes you make are created on your device; nothing is sent to us.</li>
        <li>
          When we ask scam databases about a link, we send them only the link, never the message around it.
        </li>
      </ul>
      <h2 className="text-xl font-semibold">Limitations</h2>
      <p>
        QRGUARD gives an automatic check, not a guarantee. A brand-new scam may show no known warning signs, and text
        in a blurry screenshot can be misread. When in doubt, contact the company through its official app or
        website.
      </p>
    </div>
  )
}
