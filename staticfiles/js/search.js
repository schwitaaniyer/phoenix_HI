document.addEventListener('DOMContentLoaded', function() {
    const searchInput = document.getElementById('globalSearch');
    const searchResults = document.getElementById('searchResults');
    
    if (!searchInput || !searchResults) return;
    
    // Define all searchable pages and functions
    const searchIndex = [
        { 
            title: 'Dashboard', 
            url: '/', 
            category: 'Main',
            keywords: 'home overview status'
        },
        { 
            title: 'System Logs', 
            url: '/system/logs/', 
            category: 'System',
            keywords: 'log history audit process'
        },
        { 
            title: 'System Information', 
            url: '/system/info/', 
            category: 'System',
            keywords: 'info hardware cpu memory disk'
        },
        { 
            title: 'Interfaces', 
            url: '/system/interfaces/', 
            category: 'System',
            keywords: 'interface port network physical'
        },
        { 
            title: 'Configuration', 
            url: '/system/configuration/', 
            category: 'System',
            keywords: 'config settings setup'
        },
        { 
            title: 'User Profile', 
            url: '/auth/profile/', 
            category: 'System',
            keywords: 'account user settings profile'
        },
        { 
            title: 'IPSec', 
            url: '/services/ipsec/', 
            category: 'Services',
            keywords: 'ipsec vpn security tunnel'
        },
        { 
            title: 'VPN', 
            url: '/services/vpn/', 
            category: 'Services',
            keywords: 'vpn openvpn tunnel remote'
        },
        { 
            title: 'SNMP', 
            url: '/services/snmp/', 
            category: 'Services',
            keywords: 'snmp monitoring network'
        },
        { 
            title: 'IPS/IDS', 
            url: '/services/ips_ids/', 
            category: 'Services',
            keywords: 'ips ids intrusion detection prevention snort'
        },
        { 
            title: 'Risk Analysis', 
            url: '/services/risk_analysis/', 
            category: 'Services',
            keywords: 'risk threat analysis'
        },
        { 
            title: 'Authentication', 
            url: '/services/authentication/', 
            category: 'Services',
            keywords: 'auth ldap tacacs radius login'
        },
        { 
            title: 'Routing', 
            url: '/network/routing/', 
            category: 'Network',
            keywords: 'route ip network mesh'
        },
        { 
            title: 'Firewall', 
            url: '/network/firewall/', 
            category: 'Network',
            keywords: 'firewall iptables security rules'
        },
        { 
            title: 'Optimisation', 
            url: '/network/optimisation/', 
            category: 'Network',
            keywords: 'optimize compression fec qos shaping'
        },
        { 
            title: 'Bonding', 
            url: '/network/bonding/', 
            category: 'Network',
            keywords: 'bond link aggregation'
        },
        { 
            title: 'Monitor', 
            url: '/network/monitor/', 
            category: 'Network',
            keywords: 'monitor traffic bandwidth'
        },
        { 
            title: 'nDPI', 
            url: '/network/dpi/', 
            category: 'Network',
            keywords: 'dpi deep packet inspection'
        },
        { 
            title: 'Terminal', 
            url: '/terminal/', 
            category: 'Tools',
            keywords: 'console shell command cli'
        }
    ];

    // Function to perform search
    function performSearch(query) {
        if (query.length < 2) {
            searchResults.innerHTML = '';
            searchResults.classList.remove('show');
            return;
        }

        const lowerQuery = query.toLowerCase();
        const results = searchIndex.filter(item => 
            item.title.toLowerCase().includes(lowerQuery) || 
            item.keywords.toLowerCase().includes(lowerQuery) ||
            item.category.toLowerCase().includes(lowerQuery)
        );

        displayResults(results);
    }

    // Function to display results
    function displayResults(results) {
        if (results.length === 0) {
            searchResults.innerHTML = '<div class="dropdown-item text-muted">No results found</div>';
            searchResults.classList.add('show');
            return;
        }

        let html = '';
        const categories = [...new Set(results.map(item => item.category))];
        
        categories.forEach(category => {
            html += `<h6 class="dropdown-header">${category}</h6>`;
            results.filter(item => item.category === category).forEach(item => {
                html += `
                    <a class="dropdown-item" href="${item.url}">
                        <i class="fas fa-arrow-right me-2"></i>
                        ${item.title}
                    </a>
                `;
            });
        });

        searchResults.innerHTML = html;
        searchResults.classList.add('show');
    }

    // Event listeners
    searchInput.addEventListener('input', function() {
        performSearch(this.value);
    });

    searchInput.addEventListener('focus', function() {
        if (this.value.length >= 2) {
            performSearch(this.value);
        }
    });

    document.addEventListener('click', function(e) {
        if (!searchResults.contains(e.target) && e.target !== searchInput) {
            searchResults.classList.remove('show');
        }
    });

    // Handle search button click
    const searchButton = document.getElementById('searchButton');
    if (searchButton) {
        searchButton.addEventListener('click', function() {
            performSearch(searchInput.value);
        });
    }

    // Handle Enter key
    searchInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            performSearch(this.value);
            // If there's exactly one result, navigate to it
            const items = searchResults.querySelectorAll('.dropdown-item:not(.dropdown-header)');
            if (items.length === 1) {
                window.location.href = items[0].getAttribute('href');
            }
        }
    });
});