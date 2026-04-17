# SecureMail - Anti-Phishing Email Security System

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11-blue.svg)
![Flask](https://img.shields.io/badge/flask-3.0.0-green.svg)
![Docker](https://img.shields.io/badge/docker-ready-brightgreen.svg)

> **Diploma Project**: "Research on methods of countering phishing attacks on electronic mail"  
> **Дипломная работа**: "Электрондық поштаның фишингтік шабуылдарына қарсы тұру жолдарын зерттеу"

A comprehensive email security system that detects and prevents phishing attacks using machine learning, DNS verification, OSINT techniques, and real-time monitoring.

## Features

### Core Functionality

- **Real-time Email Monitoring** - Automatic analysis of incoming emails via Gmail integration
- **Machine Learning Detection** - Phishing probability scoring using TF-IDF and Random Forest algorithms
- **DNS Security Checks** - SPF, DKIM, and DMARC verification
- **OSINT Investigation** - IP geolocation, domain analysis, and sender intelligence gathering
- **URL Security Scanner** - Detection of suspicious links and shortened URLs
- **Visual Reporting** - Interactive charts and risk assessment dashboards

### Security Modules

1. **Email Monitoring Module**
   - Gmail IMAP integration
   - EML file analysis
   - Real-time threat detection
   - Automated risk scoring (0-100)

2. **Machine Learning Engine**
   - TfidfVectorizer for text analysis
   - RandomForestClassifier for classification
   - Feature extraction from email content
   - Probability-based threat assessment

3. **DNS Verification**
   - SPF record validation
   - DKIM signature verification
   - DMARC policy analysis
   - Domain reputation checking

4. **OSINT Intelligence**
   - Email address investigation
   - IP geolocation lookup
   - Device fingerprinting
   - DNS record analysis

5. **URL Analysis**
   - Phishing link detection
   - Shortened URL expansion
   - Suspicious domain identification
   - Real-time threat scoring

6. **User Management**
   - Authentication system
   - Role-based access control (Admin/User)
   - Session management
   - Security audit logs

## Technology Stack

### Backend
- **Python 3.11** - Core programming language
- **Flask 3.0** - Web framework
- **scikit-learn** - Machine learning library
- **dnspython** - DNS operations
- **imaplib/smtplib** - Email protocols
- **Matplotlib** - Data visualization

### Frontend
- **HTML5/CSS3/JavaScript** - UI components
- **Responsive Design** - Mobile-friendly interface
- **Real-time Updates** - Dynamic content refresh
- **Interactive Visualizations** - Chart.js integration

### Infrastructure
- **Docker** - Containerization
- **MailHog** - SMTP testing
- **Gmail API** - Email integration
- **JSON Storage** - Lightweight database

## Installation

### Prerequisites

- Docker and Docker Compose
- Gmail account with App Password enabled
- Git

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/securemail.git
cd securemail
```

2. **Configure environment**
```bash
# Edit aaa.py with your Gmail credentials
GMAIL_USER = "your-email@gmail.com"
GMAIL_PASS = "your-app-password"  # 16-character app password without spaces
```

3. **Build and run with Docker**
```bash
docker-compose up --build
```

4. **Access the application**
- Open browser: `http://localhost:5000`
- Default admin credentials will be displayed in console

### Gmail Setup

1. Enable 2-Factor Authentication in your Google Account
2. Generate App Password:
   - Go to: https://myaccount.google.com/apppasswords
   - Select "Mail" and your device
   - Copy the 16-character password (remove spaces)
3. Enable IMAP in Gmail settings

## Usage

### 1. Authentication
- Register a new account or login
- Admin users have full access to all features

### 2. Email Monitoring
- Click "Мониторинг" → "Gmail"
- Click "Запустить мониторинг" to start
- System automatically fetches and analyzes emails

### 3. Manual Analysis
- **EML Files**: Upload .eml files for analysis
- **URLs**: Check suspicious links
- **DNS**: Verify domain security records

### 4. OSINT Investigation
- Analyze email addresses for domain information
- Check IP geolocation and reputation
- Parse email headers for sender intelligence

### 5. Reports
- View phishing probability scores
- See DNS security status
- Review risk assessments and recommendations

## Project Structure

```
securemail/
├── app/
│   ├── aaa.py              # Main Flask application
│   ├── auth.py             # Authentication module
│   ├── osint_routes.py     # OSINT functions
│   ├── ml_detector.py      # Machine learning model
│   └── osint_analyzer.py   # Employee database
├── templates/
│   ├── index.html          # Main interface
│   └── login.html          # Authentication page
├── static/
│   └── style.css           # Styling
├── requirements.txt        # Python dependencies
├── Dockerfile             # Container configuration
└── docker-compose.yml     # Orchestration
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout

### Email Analysis
- `POST /api/analyze` - Analyze email text
- `POST /api/upload-eml` - Upload EML file
- `GET /api/received-emails` - Get monitored emails

### DNS Checks
- `POST /api/check-spf` - Verify SPF record
- `POST /api/check-dkim` - Verify DKIM
- `POST /api/check-dmarc` - Verify DMARC

### OSINT
- `POST /api/osint/email` - Email investigation
- `POST /api/osint/ip` - IP geolocation

### Monitoring
- `POST /api/gmail-monitoring/start` - Start monitoring
- `POST /api/gmail-monitoring/stop` - Stop monitoring
- `POST /api/fetch-gmail` - Manual fetch

## Machine Learning Model

The system uses a supervised learning approach:

1. **Feature Extraction**
   - TF-IDF vectorization of email text
   - Subject line analysis
   - Sender domain patterns
   - URL presence detection

2. **Classification**
   - Random Forest Classifier
   - Probability scoring (0-100)
   - Multi-factor risk assessment

3. **Training Data**
   - Phishing email samples
   - Legitimate email samples
   - Continuous model improvement

## Security Considerations

- Passwords hashed with SHA-256
- Session-based authentication
- HTTPS recommended for production
- Rate limiting on API endpoints
- Input validation and sanitization
- XSS protection
- CSRF tokens (recommended)

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Rymtai Anel**

- Year: 2026
- Thesis: "Research on methods of countering phishing attacks on electronic mail"

## Acknowledgments

- Al-Farabi Kazakh National University
- Scientific advisor: [Name]
- Department of Information Security

## Screenshots

### Main Dashboard
![Dashboard](screenshots/dashboard.png)

### Email Analysis
![Analysis](screenshots/analysis.png)

### OSINT Investigation
![OSINT](screenshots/osint.png)

### DNS Verification
![DNS](screenshots/dns.png)

## Roadmap

- [ ] Integration with more email providers
- [ ] Advanced ML models (Deep Learning)
- [ ] Browser extension
- [ ] Mobile application
- [ ] API for third-party integration
- [ ] Real-time threat intelligence feeds
- [ ] Automated response system
- [ ] Multi-language support

## Support

If you encounter any issues or have questions:

1. Check the [Issues](https://github.com/yourusername/securemail/issues) page
2. Open a new issue with detailed description
3. Contact: your-email@example.com

## Citation

If you use this project in your research, please cite:

```bibtex
@mastersthesis{rymtai2025securemail,
  title={Research on methods of countering phishing attacks on electronic mail},
  author={Rymtai, Anel},
  year={2025},
  school={Al-Farabi Kazakh National University}
}
```

---
