"""
MCP Server - Subscription Manager
Serveur MCP pour gérer et suivre les abonnements via email
"""

from mcp.server.fastmcp import FastMCP
from pydantic import Field, BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import imaplib
import email
from email.header import decode_header
import re
import json
import os
from enum import Enum

# Configuration
mcp = FastMCP("Subscription Manager", port=3000, stateless_http=True, debug=True)

# Modèles de données
@dataclass
class Subscription:
    """Modèle pour représenter un abonnement"""
    service_name: str
    amount: Optional[float] = None
    currency: Optional[str] = None
    billing_cycle: Optional[str] = None  # monthly, yearly, etc.
    next_billing_date: Optional[str] = None
    status: str = "active"
    email_from: str = ""
    detected_date: str = ""

class EmailProvider(Enum):
    """Fournisseurs de messagerie supportés"""
    GMAIL = ("imap.gmail.com", 993)
    OUTLOOK = ("outlook.office365.com", 993)
    YAHOO = ("imap.mail.yahoo.com", 993)
    CUSTOM = ("", 993)

class EmailCredentials(BaseModel):
    """Modèle pour les identifiants email"""
    email: str
    password: str
    provider: str = "gmail"
    imap_server: Optional[str] = None
    imap_port: Optional[int] = 993

# Patterns de détection des abonnements
SUBSCRIPTION_PATTERNS = {
    "netflix": {
        "sender_patterns": ["netflix.com", "account@netflix.com"],
        "subject_patterns": ["payment", "subscription", "billing", "facture", "abonnement"],
        "service_name": "Netflix"
    },
    "spotify": {
        "sender_patterns": ["spotify.com", "no-reply@spotify.com"],
        "subject_patterns": ["payment", "premium", "subscription", "facture"],
        "service_name": "Spotify"
    },
    "amazon_prime": {
        "sender_patterns": ["amazon.com", "prime@amazon"],
        "subject_patterns": ["prime membership", "amazon prime", "abonnement prime"],
        "service_name": "Amazon Prime"
    },
    "disney_plus": {
        "sender_patterns": ["disneyplus.com", "disney+"],
        "subject_patterns": ["payment", "subscription", "facture"],
        "service_name": "Disney+"
    },
    "apple": {
        "sender_patterns": ["apple.com", "itunes.com"],
        "subject_patterns": ["receipt", "subscription", "facture", "reçu"],
        "service_name": "Apple Services"
    },
    "google": {
        "sender_patterns": ["google.com", "payments-noreply@google.com"],
        "subject_patterns": ["payment", "google one", "youtube premium", "facture"],
        "service_name": "Google Services"
    },
    "microsoft": {
        "sender_patterns": ["microsoft.com", "office365"],
        "subject_patterns": ["subscription", "office", "payment", "facture"],
        "service_name": "Microsoft/Office 365"
    }
}

# Gestionnaire d'emails
class EmailManager:
    """Classe pour gérer la connexion et la récupération des emails"""
    
    def __init__(self, credentials: EmailCredentials):
        self.credentials = credentials
        self.connection = None
        
    def connect(self) -> bool:
        """Se connecter au serveur IMAP"""
        try:
            # Déterminer le serveur IMAP
            if self.credentials.imap_server:
                server = self.credentials.imap_server
                port = self.credentials.imap_port or 993
            else:
                provider = EmailProvider[self.credentials.provider.upper()]
                server, port = provider.value
            
            # Connexion IMAP
            self.connection = imaplib.IMAP4_SSL(server, port)
            self.connection.login(self.credentials.email, self.credentials.password)
            return True
        except Exception as e:
            print(f"Erreur de connexion: {str(e)}")
            return False
    
    def disconnect(self):
        """Se déconnecter du serveur IMAP"""
        if self.connection:
            try:
                self.connection.logout()
            except:
                pass
    
    def search_subscription_emails(self, days_back: int = 90) -> List[Dict[str, Any]]:
        """Rechercher les emails d'abonnement"""
        if not self.connection:
            return []
        
        emails_data = []
        
        try:
            # Sélectionner la boîte de réception
            self.connection.select('INBOX')
            
            # Calculer la date de recherche
            since_date = (datetime.now() - timedelta(days=days_back)).strftime("%d-%b-%Y")
            
            # Rechercher les emails récents
            _, message_ids = self.connection.search(None, f'(SINCE "{since_date}")')
            
            for msg_id in message_ids[0].split():
                try:
                    # Récupérer l'email
                    _, msg_data = self.connection.fetch(msg_id, '(RFC822)')
                    email_body = msg_data[0][1]
                    email_message = email.message_from_bytes(email_body)
                    
                    # Extraire les informations
                    email_info = self._parse_email(email_message)
                    if email_info:
                        emails_data.append(email_info)
                        
                except Exception as e:
                    print(f"Erreur lors du traitement d'un email: {str(e)}")
                    continue
                    
        except Exception as e:
            print(f"Erreur lors de la recherche: {str(e)}")
            
        return emails_data
    
    def _parse_email(self, email_message) -> Optional[Dict[str, Any]]:
        """Parser un email pour extraire les informations"""
        try:
            # Décoder le sujet
            subject = ""
            if email_message["Subject"]:
                subject_parts = decode_header(email_message["Subject"])
                subject = ""
                for part, encoding in subject_parts:
                    if isinstance(part, bytes):
                        subject += part.decode(encoding or 'utf-8', errors='ignore')
                    else:
                        subject += str(part)
            
            # Obtenir l'expéditeur
            from_email = email_message.get("From", "")
            date_str = email_message.get("Date", "")
            
            # Extraire le corps du message
            body = self._get_email_body(email_message)
            
            return {
                "subject": subject,
                "from": from_email,
                "date": date_str,
                "body": body[:1000] if body else "",  # Limiter la taille
            }
            
        except Exception as e:
            print(f"Erreur de parsing: {str(e)}")
            return None
    
    def _get_email_body(self, email_message) -> str:
        """Extraire le corps du message"""
        body = ""
        
        if email_message.is_multipart():
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    try:
                        body = part.get_payload(decode=True).decode('utf-8', errors='ignore')
                        break
                    except:
                        continue
        else:
            try:
                body = email_message.get_payload(decode=True).decode('utf-8', errors='ignore')
            except:
                body = str(email_message.get_payload())
                
        return body

# Analyseur d'abonnements
class SubscriptionAnalyzer:
    """Classe pour analyser et détecter les abonnements dans les emails"""
    
    @staticmethod
    def detect_subscriptions(emails: List[Dict[str, Any]]) -> List[Subscription]:
        """Détecter les abonnements dans une liste d'emails"""
        subscriptions = {}
        
        for email_data in emails:
            subscription = SubscriptionAnalyzer._analyze_email(email_data)
            if subscription:
                # Éviter les doublons en utilisant le nom du service comme clé
                if subscription.service_name not in subscriptions:
                    subscriptions[subscription.service_name] = subscription
                    
        return list(subscriptions.values())
    
    @staticmethod
    def _analyze_email(email_data: Dict[str, Any]) -> Optional[Subscription]:
        """Analyser un email pour détecter un abonnement"""
        from_email = email_data.get("from", "").lower()
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body", "").lower()
        
        # Vérifier chaque pattern d'abonnement
        for service_key, patterns in SUBSCRIPTION_PATTERNS.items():
            # Vérifier l'expéditeur
            sender_match = any(pattern in from_email for pattern in patterns["sender_patterns"])
            
            # Vérifier le sujet
            subject_match = any(pattern in subject for pattern in patterns["subject_patterns"])
            
            if sender_match or subject_match:
                # Extraire les montants si possible
                amount, currency = SubscriptionAnalyzer._extract_amount(body + " " + subject)
                
                # Extraire la période de facturation
                billing_cycle = SubscriptionAnalyzer._extract_billing_cycle(body + " " + subject)
                
                return Subscription(
                    service_name=patterns["service_name"],
                    amount=amount,
                    currency=currency,
                    billing_cycle=billing_cycle,
                    email_from=email_data.get("from", ""),
                    detected_date=email_data.get("date", ""),
                    status="active"
                )
                
        # Détection générique si aucun pattern spécifique ne correspond
        if any(word in subject or word in from_email for word in ["subscription", "payment", "billing", "abonnement", "facture"]):
            # Essayer d'extraire le nom du service
            service_name = SubscriptionAnalyzer._extract_service_name(from_email)
            amount, currency = SubscriptionAnalyzer._extract_amount(body + " " + subject)
            
            return Subscription(
                service_name=service_name or "Service Inconnu",
                amount=amount,
                currency=currency,
                email_from=email_data.get("from", ""),
                detected_date=email_data.get("date", ""),
                status="active"
            )
            
        return None
    
    @staticmethod
    def _extract_amount(text: str) -> tuple[Optional[float], Optional[str]]:
        """Extraire le montant et la devise du texte"""
        # Patterns pour détecter les montants
        patterns = [
            r'(\d+[.,]\d{2})\s*(€|EUR|eur)',
            r'(\d+[.,]\d{2})\s*(\$|USD|usd)',
            r'(\d+[.,]\d{2})\s*(£|GBP|gbp)',
            r'€\s*(\d+[.,]\d{2})',
            r'\$\s*(\d+[.,]\d{2})',
            r'£\s*(\d+[.,]\d{2})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text)
            if match:
                amount_str = match.group(1).replace(',', '.')
                try:
                    amount = float(amount_str)
                    # Déterminer la devise
                    if '€' in match.group(0) or 'EUR' in match.group(0).upper():
                        return amount, 'EUR'
                    elif '$' in match.group(0) or 'USD' in match.group(0).upper():
                        return amount, 'USD'
                    elif '£' in match.group(0) or 'GBP' in match.group(0).upper():
                        return amount, 'GBP'
                except:
                    continue
                    
        return None, None
    
    @staticmethod
    def _extract_billing_cycle(text: str) -> Optional[str]:
        """Extraire la période de facturation"""
        text = text.lower()
        
        if any(word in text for word in ["monthly", "month", "mensuel", "mois"]):
            return "monthly"
        elif any(word in text for word in ["yearly", "annual", "year", "annuel", "an"]):
            return "yearly"
        elif any(word in text for word in ["weekly", "week", "hebdomadaire", "semaine"]):
            return "weekly"
        elif any(word in text for word in ["quarterly", "trimestre"]):
            return "quarterly"
            
        return None
    
    @staticmethod
    def _extract_service_name(from_email: str) -> Optional[str]:
        """Extraire le nom du service depuis l'email de l'expéditeur"""
        # Nettoyer l'email
        from_email = from_email.lower()
        
        # Extraire le domaine
        match = re.search(r'@([a-zA-Z0-9.-]+)', from_email)
        if match:
            domain = match.group(1)
            # Retirer les extensions communes
            service_name = domain.replace('.com', '').replace('.fr', '').replace('.net', '')
            # Capitaliser
            return service_name.capitalize()
            
        return None

# Tools MCP
@mcp.tool(
    title="Connect Email",
    description="Se connecter à un compte email pour récupérer les abonnements"
)
def connect_email(
    email: str = Field(description="Adresse email"),
    password: str = Field(description="Mot de passe ou mot de passe d'application"),
    provider: str = Field(description="Fournisseur email: gmail, outlook, yahoo, ou custom", default="gmail"),
    imap_server: Optional[str] = Field(description="Serveur IMAP personnalisé (optionnel)", default=None),
    imap_port: Optional[int] = Field(description="Port IMAP (optionnel)", default=993)
) -> Dict[str, Any]:
    """Se connecter à un compte email"""
    
    credentials = EmailCredentials(
        email=email,
        password=password,
        provider=provider,
        imap_server=imap_server,
        imap_port=imap_port
    )
    
    manager = EmailManager(credentials)
    
    if manager.connect():
        # Stocker temporairement la connexion (dans un vrai système, utiliser une session)
        return {
            "success": True,
            "message": f"Connecté avec succès à {email}",
            "provider": provider
        }
    else:
        return {
            "success": False,
            "message": "Échec de la connexion. Vérifiez vos identifiants et paramètres.",
            "hint": "Pour Gmail, utilisez un mot de passe d'application. Pour Outlook, activez IMAP."
        }

@mcp.tool(
    title="Fetch Subscriptions",
    description="Récupérer et analyser les abonnements depuis les emails"
)
def fetch_subscriptions(
    email: str = Field(description="Adresse email"),
    password: str = Field(description="Mot de passe ou mot de passe d'application"),
    provider: str = Field(description="Fournisseur email", default="gmail"),
    days_back: int = Field(description="Nombre de jours à analyser", default=90)
) -> Dict[str, Any]:
    """Récupérer les abonnements depuis les emails"""
    
    credentials = EmailCredentials(
        email=email,
        password=password,
        provider=provider
    )
    
    manager = EmailManager(credentials)
    
    if not manager.connect():
        return {
            "success": False,
            "message": "Impossible de se connecter au compte email",
            "subscriptions": []
        }
    
    try:
        # Rechercher les emails
        emails = manager.search_subscription_emails(days_back)
        
        # Analyser les abonnements
        analyzer = SubscriptionAnalyzer()
        subscriptions = analyzer.detect_subscriptions(emails)
        
        # Calculer les statistiques
        total_monthly = 0
        total_yearly = 0
        
        for sub in subscriptions:
            if sub.amount:
                if sub.billing_cycle == "monthly":
                    total_monthly += sub.amount
                elif sub.billing_cycle == "yearly":
                    total_yearly += sub.amount / 12
        
        # Formater les résultats
        subscription_list = []
        for sub in subscriptions:
            subscription_list.append({
                "service": sub.service_name,
                "amount": sub.amount,
                "currency": sub.currency,
                "billing_cycle": sub.billing_cycle,
                "status": sub.status,
                "detected_from": sub.email_from,
                "last_detected": sub.detected_date
            })
        
        return {
            "success": True,
            "message": f"Trouvé {len(subscriptions)} abonnement(s)",
            "subscriptions": subscription_list,
            "statistics": {
                "total_subscriptions": len(subscriptions),
                "estimated_monthly_cost": round(total_monthly + total_yearly, 2),
                "emails_analyzed": len(emails)
            }
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Erreur lors de l'analyse: {str(e)}",
            "subscriptions": []
        }
    finally:
        manager.disconnect()

@mcp.tool(
    title="Get Subscription Summary",
    description="Obtenir un résumé des abonnements détectés"
)
def get_subscription_summary(
    email: str = Field(description="Adresse email"),
    password: str = Field(description="Mot de passe"),
    provider: str = Field(description="Fournisseur email", default="gmail")
) -> str:
    """Générer un résumé textuel des abonnements"""
    
    result = fetch_subscriptions(email, password, provider, days_back=90)
    
    if not result["success"]:
        return f"Erreur: {result['message']}"
    
    subscriptions = result["subscriptions"]
    stats = result["statistics"]
    
    if not subscriptions:
        return "Aucun abonnement détecté dans vos emails récents."
    
    summary = f"📊 RÉSUMÉ DE VOS ABONNEMENTS\n"
    summary += f"{'='*40}\n\n"
    summary += f"Total d'abonnements détectés: {stats['total_subscriptions']}\n"
    summary += f"Coût mensuel estimé: {stats['estimated_monthly_cost']} EUR\n"
    summary += f"Emails analysés: {stats['emails_analyzed']}\n\n"
    
    summary += "📋 LISTE DES ABONNEMENTS:\n"
    summary += f"{'='*40}\n"
    
    for sub in subscriptions:
        summary += f"\n✓ {sub['service']}\n"
        if sub['amount']:
            summary += f"  💰 {sub['amount']} {sub['currency'] or 'EUR'}"
            if sub['billing_cycle']:
                summary += f" ({sub['billing_cycle']})\n"
            else:
                summary += "\n"
        else:
            summary += "  💰 Montant non détecté\n"
        
        summary += f"  📧 Source: {sub['detected_from'][:50]}...\n"
    
    return summary

@mcp.resource(
    uri="subscription://{service_name}",
    description="Obtenir les détails d'un abonnement spécifique",
    name="Subscription Details"
)
def get_subscription_details(service_name: str) -> str:
    """Obtenir les détails d'un abonnement spécifique"""
    # Dans un vrai système, cela récupérerait depuis une base de données
    return f"Détails de l'abonnement {service_name}: [Nécessite une connexion email active]"

@mcp.prompt("subscription_analysis")
def analyze_subscriptions_prompt(
    email: str = Field(description="Email à analyser"),
    focus: str = Field(description="Focus de l'analyse: cost, usage, ou optimization", default="cost")
) -> str:
    """Générer un prompt d'analyse des abonnements"""
    
    prompts = {
        "cost": f"Analysez les coûts des abonnements du compte {email}. Identifiez les abonnements les plus chers et suggérez des optimisations possibles.",
        "usage": f"Évaluez l'utilisation des abonnements du compte {email}. Identifiez les services sous-utilisés.",
        "optimization": f"Proposez une stratégie d'optimisation des abonnements pour {email}. Suggérez des alternatives et des regroupements possibles."
    }
    
    return prompts.get(focus, prompts["cost"])
if __name__ == "__main__":
    mcp.run(transport="streamable-http")