import React, { useState, useRef, useEffect } from 'react';
import Image from 'next/image';
import { INSECURE_API_PATTERNS, KEY_PATTERNS } from '@/utils/regex-rules';

export default function SecurityScanner() {
  const [url, setUrl] = useState('');
  const [scanResult, setScanResult] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [showInfo, setShowInfo] = useState(false);
  const chatEndRef = useRef(null);

  useEffect(() => {
    if (chatEndRef.current) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [scanResult, errorMessage]);

  async function handleScan(e) {
    e.preventDefault();
    setIsLoading(true);
    setScanResult(null);
    setErrorMessage(null);
    try {
      const res = await fetch('/api/extract', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || 'Scan failed');
      }
      setScanResult(await res.json());
      setIsLoading(false);
    } catch (err) {
      setErrorMessage(err.message);
      setIsLoading(false);
    }
  }

  const renderBubble = (children, isError = false) => (
    <div className={`max-w-2xl mx-auto ${isError ? 'justify-start' : 'justify-start'} flex`}>
      <div className={`${isError ? 'bg-red-100 border-red-200' : 'bg-white border-gray-200'} border rounded-lg p-4 shadow-sm`}>
        {children}
      </div>
    </div>
  );

  return (
    <div className="flex flex-col h-screen bg-gray-50">
      <header className="bg-white shadow p-4">
        <div className="max-w-2xl mx-auto flex items-center justify-between">
          <div className="flex items-center">
            <Image src="/crackable.png" alt="Logo" width={40} height={40} />
            <h1 className="ml-2 text-2xl font-bold">CrackAble</h1>
          </div>
          <button
            onClick={() => setShowInfo(!showInfo)}
            className="text-sm text-blue-600 hover:text-blue-800"
          >
            {showInfo ? 'Hide Info' : 'Show Info'}
          </button>
        </div>
      </header>

      {showInfo && (
        <div className="max-w-2xl mx-auto my-4 p-4 bg-white border rounded shadow-sm overflow-auto">
          <h2 className="text-lg font-semibold mb-2">🔍 Applied Regex Patterns</h2>
          <div className="mb-4">
            <h3 className="font-medium">Key Patterns:</h3>
            <ul className="list-disc list-inside text-sm">
              {Object.entries(KEY_PATTERNS).map(([name, regex]) => (
                <li key={name}>
                  <strong>{name}:</strong> <code>{regex.toString()}</code>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <h3 className="font-medium">Insecure API Patterns:</h3>
            <ul className="list-disc list-inside text-sm">
              {Object.entries(INSECURE_API_PATTERNS).map(([name, regex]) => (
                <li key={name}>
                  <strong>{name}:</strong> <code>{regex.toString()}</code>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}


      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {!scanResult && !errorMessage &&
          renderBubble(<p className="text-gray-600">Hello! Paste a URL below and hit “Scan” to detect secrets & API issues.</p>)
        }

        {errorMessage && renderBubble(<p className="text-red-700">{errorMessage}</p>, true)}

        {scanResult && (
          <>
            {renderBubble(
              <p><strong>Scan complete!</strong><br />Results for <em>{scanResult.scannedUrl}</em> at {new Date(scanResult.scannedAt).toLocaleTimeString()}.</p>
            )}

            {renderBubble(
              <>
                <div className="flex items-center mb-2">
                  <h2 className="ml-2 font-semibold text-lg">🔑 Secrets/Keys Detected</h2>
                </div>
                {scanResult.secrets.length > 0 ? (
                  <ul className="space-y-2">
                    {scanResult.secrets.map((s, i) => (
                      <li key={i} className="bg-red-50 p-2 rounded">
                        <strong>Line {s.line}</strong> — {s.keyType}: <code className="text-sm">{s.match}</code>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-gray-500">No secrets found.</p>
                )}
              </>
            )}

            {renderBubble(
              <>
                <div className="flex items-center mb-2">
                  <h2 className="ml-2 font-semibold text-lg">🌐 API Issues Detected</h2>
                  <h3 className="ml-2 text-sm text-gray-500">BEWARE: These issues may not neccesarily be dangeorous, but they are worth checking out.</h3>
                </div>
                {scanResult.apiIssues.length > 0 ? (
                  <ul className="space-y-2">
                    {scanResult.apiIssues.map((i, idx) => (
                      <li key={idx} className="bg-yellow-50 p-2 rounded">
                        <strong>Line {i.line}</strong> — {i.issueType} <span className="text-xs text-gray-500">({i.severity})</span><br />
                        <code className="text-sm">{i.match}</code>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-gray-500">No API issues found.</p>
                )}
              </>
            )}
          </>
        )}
        <div ref={chatEndRef} />
      </div>

      <form onSubmit={handleScan} className="bg-white p-4 flex items-center gap-2 shadow-inner">
        <input
          type="url"
          className="flex-1 border border-gray-300 rounded-full px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-400"
          placeholder="https://example.com..."
          value={url}
          onChange={e => setUrl(e.target.value)}
          required
        />
        <button
          type="submit"
          className="bg-blue-600 hover:bg-blue-700 text-white rounded-full px-6 py-2 transition"
        >
          {isLoading ? 'Scanning...' : 'Scan'}
        </button>
      </form>

    </div>
  );
}