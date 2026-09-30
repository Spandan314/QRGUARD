export default function About() {
  return (
    <div className="prose max-w-3xl space-y-4 dark:prose-invert">
      <h1 className="text-3xl font-bold">About QRGUARD</h1>
      <p>
        QRGUARD is an intelligent QR and digital scam detection system built as a final-year Computer Engineering
        project. It combines explainable rules, URL analysis, text recognition and threat-intelligence sources.
      </p>
      <h2 className="text-xl font-semibold">How it decides</h2>
      <ul className="list-disc space-y-1 pl-6">
        <li>Every result lists the warning signs it found and how many points each one added.</li>
        <li>The risk level comes only from the score. Verification is shown separately and never changes the score.</li>
        <li>"Not found on a threat list" never makes something look safer.</li>
      </ul>
      <h2 className="text-xl font-semibold">Privacy</h2>
      <ul className="list-disc space-y-1 pl-6">
        <li>Links are never opened for you; the server only checks where shortened links redirect.</li>
        <li>Messages, screenshots and QR contents are not stored or logged.</li>
        <li>QR codes you create are made in your browser; nothing is sent to the server.</li>
        <li>
          If external threat-intelligence services are enabled, only the link itself is sent to them – never the
          message around it.
        </li>
      </ul>
      <h2 className="text-xl font-semibold">Limitations</h2>
      <p>
        QRGUARD gives an automated assessment, not a guarantee. New scams may not show known warning signs, and text
        recognition can misread screenshots. When in doubt, contact the organisation through its official app or
        website.
      </p>
    </div>
  )
}
