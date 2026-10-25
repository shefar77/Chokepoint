/** Dynamic cinematic intro component for the demo video. */

import { useEffect, useState } from 'react';
import './Intro.css';

export function IntroPage() {
  const [step, setStep] = useState(0);

  useEffect(() => {
    const timers = [
      setTimeout(() => setStep(1), 1000),   // Show Chokepoint
      setTimeout(() => setStep(2), 3500),   // Show Team Name
      setTimeout(() => setStep(3), 5500),   // Show Members
    ];
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="intro-container">
      <div className={`intro-content step-${step}`}>
        <div className="glitch-wrapper">
          <h1 className="intro-title">CHOKEPOINT</h1>
        </div>

        <div className="intro-subtitle">
          <span className="line-1">Stop ranking vulnerabilities.</span>
          <span className="line-2">Start cutting attack paths.</span>
        </div>

        <div className="team-info">
          <div className="team-name">Sleep Deprived</div>
          <div className="members">
            <span>Jay Dosi</span>
            <span className="dot">·</span>
            <span>Vaibhav Tandon</span>
            <span className="dot">·</span>
            <span>Farhan Sheikh</span>
          </div>
        </div>

        <div className="track-info">
          Hackathon 2026: Agents That Act on Connected Data
        </div>
      </div>

      <div className="scan-line"></div>
    </div>
  );
}
