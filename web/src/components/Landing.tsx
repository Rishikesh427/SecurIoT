import { Logo } from './Logo';
import { TurtleCompanion, TurtleParade } from './TurtleParade';
import { Button } from './ui';

export function Landing({ onEnter, authenticated = false }: { onEnter: () => void; authenticated?: boolean }) {
  return <div className="flex min-h-screen flex-col bg-white text-ink">
    <header className="mx-auto flex w-full max-w-5xl items-center justify-between gap-4 px-6 py-6">
      <div className="flex items-center gap-2"><Logo size={30} /><span className="font-semibold">CasaWarden</span></div>
      <Button onClick={onEnter}>{authenticated ? "Open Dashboard" : "Log in / Sign up"}</Button>
    </header>
    <main className="mx-auto w-full max-w-5xl flex-1 px-6 py-12 sm:py-20">
      <TurtleCompanion />
      <h1 className="mt-5 max-w-3xl text-4xl font-semibold leading-tight tracking-tight sm:text-6xl">Security for the devices you can’t patch.</h1>
      <p className="mt-6 max-w-2xl text-xl leading-relaxed text-ink-2">Your camera, smart plug, and TV share one home network. CasaWarden helps you understand their risks and take action at the router.</p>
      <Button variant="primary" className="mt-8" onClick={onEnter}>Open CasaWarden</Button>
      <div className="mt-16 space-y-8">
        {[
          ['See your network', 'Discover connected devices, inspect their risk scores, and follow activity over time.'],
          ['Understand the warning', 'Review detection evidence, rules-based risk breakdowns, and plain-language guidance from the Gemini advisor.'],
          ['Choose the response', 'Block internet access, quarantine a device on the Raspberry Pi router, and restore access when you are ready. Review the result in the audit log.'],
        ].map(([title, copy], i) => <section key={title} className="flex max-w-2xl items-start gap-4"><TurtleCompanion variant={i + 1} /><div><h2 className="text-xl font-medium">{title}</h2><p className="mt-2 leading-relaxed text-ink-2">{copy}</p></div></section>)}
      </div>
    </main>
    <TurtleParade />
  </div>;
}
