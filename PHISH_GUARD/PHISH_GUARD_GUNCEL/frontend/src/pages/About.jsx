import React from 'react';
import { Link } from 'react-router-dom';

export default function About() {
    const team = [
        { name: 'Aylin Elif Gökdemir', role: 'Kurucu Ortak / Geliştirici' },
        { name: 'Ceren Dıvar', role: 'Kurucu Ortak / Geliştirici' },
        { name: 'Tuğba Sümer', role: 'Kurucu Ortak / Geliştirici' },
        { name: 'Özlem Akkuş', role: 'Kurucu Ortak / Geliştirici' },
        { name: 'Sudenaz Demirci', role: 'Kurucu Ortak / Geliştirici' },
    ];

    return (
        <div className="min-h-screen flex flex-col relative overflow-hidden">
            {/* Background Decor */}
            <div className="absolute inset-0 bg-cyber-900 z-0" />
            <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-cyber-primary/10 blur-[100px] rounded-full pointer-events-none" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyber-secondary/10 blur-[100px] rounded-full pointer-events-none" />

            {/* Navbar (Simplified for About Page) */}
            <nav className="border-b border-gray-800 bg-cyber-900/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <Link to="/" className="flex items-center gap-2">
                            <div className="w-3 h-3 bg-cyber-primary rounded-full" />
                            <h1 className="text-xl font-bold tracking-tighter text-white">
                                PHISH<span className="text-cyber-primary">GUARD</span>
                            </h1>
                        </Link>
                        <div className="flex gap-6">
                            <Link to="/dashboard" className="text-gray-400 hover:text-white transition text-sm font-medium">Dashboard</Link>
                            <Link to="/login" className="text-gray-400 hover:text-white transition text-sm font-medium">Login</Link>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="flex-1 relative z-10 w-full max-w-7xl mx-auto px-6 py-12">

                {/* Project Vision Section */}
                <section className="mb-20 text-center max-w-4xl mx-auto">
                    <h2 className="text-4xl md:text-5xl font-bold text-white tracking-tight mb-8">
                        Proje <span className="text-cyber-primary">Vizyonu</span>
                    </h2>
                    <div className="cyber-card p-8 md:p-12 relative overflow-hidden group">
                        <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyber-primary to-cyber-secondary" />
                        <p className="text-gray-300 text-lg md:text-xl leading-relaxed font-light">
                            "Günümüzde siber saldırıların en yaygın başlangıç noktası olan e-postalar, bireysel ve kurumsal veri güvenliğini tehdit etmektedir.
                            <strong className="text-white"> PhishGuard</strong> projesi, gelişmiş yapay zeka algoritmalarını kullanarak e-posta içeriklerini analiz etmek
                            ve potansiyel oltalama (phishing) girişimlerini yüksek doğrulukla tespit etmek amacıyla geliştirilmiştir.
                            Hedefimiz, kullanıcıların dijital güvenliğini sağlamak ve siber farkındalığı artırarak bilgi hırsızlığının önüne geçmektir."
                        </p>
                    </div>
                </section>

                {/* Team Section */}
                <section>
                    <div className="flex items-center justify-center gap-4 mb-12">
                        <h3 className="text-3xl font-bold text-white uppercase tracking-widest">Geliştirici Ekip</h3>
                        <div className="h-px bg-gray-800 flex-1 max-w-[100px]" />
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 justify-center">
                        {team.map((member, index) => (
                            <div key={index} className="cyber-card p-6 flex items-center gap-4 hover:border-cyber-primary/50 transition-all duration-300 group hover:-translate-y-1">
                                <div className="w-16 h-16 rounded-full bg-cyber-800 border-2 border-gray-700 flex items-center justify-center text-xl font-bold text-cyber-secondary group-hover:border-cyber-primary group-hover:text-cyber-primary transition-colors focus:ring-2">
                                    {member.name.split(' ').map(n => n[0]).join('').slice(0, 2)}
                                </div>
                                <div>
                                    <h4 className="text-white font-bold text-lg">{member.name}</h4>
                                    <p className="text-cyber-primary text-xs uppercase tracking-wider font-mono">{member.role}</p>
                                </div>
                            </div>
                        ))}
                    </div>
                </section>

            </main>
        </div>
    );
}
