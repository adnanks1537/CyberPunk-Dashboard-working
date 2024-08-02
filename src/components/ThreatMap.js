import React from 'react';
import './ThreatMap.css';

const ThreatMap = () => {
    const dummyIPData = [
        { ip: '192.168.1.1', location: 'New York, USA' },
        { ip: '10.0.0.1', location: 'Los Angeles, USA' },
        { ip: '172.16.0.1', location: 'London, UK' },
        { ip: '203.0.113.0', location: 'Tokyo, Japan' },
        { ip: '198.51.100.0', location: 'Sydney, Australia' },
    ];

    return (
        <div className="threat-map-container">
            {dummyIPData.map((data, index) => (
                <div key={index} className="threat-map-entry">
                    <strong>IP:</strong> {data.ip} <strong>Location:</strong> {data.location}
                </div>
            ))}
        </div>
    );
};

export default ThreatMap;
