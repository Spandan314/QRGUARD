const TIPS = [
  { title: 'Never share an OTP, PIN or password', text: 'Banks, UPI apps and the government never ask for them by call, SMS or chat.' },
  { title: 'Scanning a UPI QR code sends money', text: 'You never need to scan a code or enter your UPI PIN to receive money, a refund or a prize.' },
  { title: 'Check the real domain', text: 'Look at the part just before .com / .in: sbi.co.in.kyc-update.xyz belongs to kyc-update.xyz, not SBI.' },
  { title: 'Urgency is a warning sign', text: '"Your account will be blocked today" is designed to make you act before you think.' },
  { title: 'No fees for jobs or prizes', text: 'Genuine employers and lotteries do not ask for a registration fee or "tax" in advance.' },
  { title: 'Do not install apps a caller asks for', text: 'Screen-sharing apps such as AnyDesk give a stranger control of your phone.' },
  { title: 'Report fraud quickly', text: 'In India, call 1930 or report at cybercrime.gov.in. Tell your bank immediately.' },
]

export default function SecurityTips() {
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Safety tips</h1>
      <ul className="grid gap-4 sm:grid-cols-2">
        {TIPS.map((tip) => (
          <li key={tip.title} className="rounded-2xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-900">
            <h2 className="font-semibold">{tip.title}</h2>
            <p className="mt-1 text-slate-600 dark:text-slate-300">{tip.text}</p>
          </li>
        ))}
      </ul>
    </div>
  )
}
