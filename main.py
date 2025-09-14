"""
MCP Server - Subscription Manager avec Google OAuth (Version HTTP uniquement)
Serveur MCP pour gérer et suivre les abonnements via Gmail sans dépendances Google
"""

from fastmcp import FastMCP
from fastmcp.server.auth.providers.google import GoogleProvider
from fastmcp.server.dependencies import get_access_token
from pydantic import Field, BaseModel
from typing import List, Dict, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
import email
from email.header import decode_header
import re
import json
import os
from enum import Enum
import base64
import requests
import urllib.parse

# Configuration OAuth Google
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
BASE_URL = "http://127.0.0.1:3000"

# Configuration du provider Google OAuth
auth_provider = GoogleProvider(
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    base_url=BASE_URL,
    required_scopes=[
        "openid",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "https://www.googleapis.com/auth/gmail.readonly"
    ],
    redirect_path="/auth/callback"
)

# Initialisation du serveur MCP
mcp = FastMCP(
    name="Subscription Manager avec Google Auth",
    auth=auth_provider,
    port=3000,
    stateless_http=True,
    debug=True
)

# Modèles de données
@dataclass
class Subscription:
    service_name: str
    amount: Optional[float] = None
    currency: Optional[str] = None
    billing_cycle: Optional[str] = None
    next_billing_date: Optional[str] = None
    status: str = "active"
    email_from: str = ""
    detected_date: str = ""
    user_email: str = ""

# Patterns de détection des abonnements
SUBSCRIPTION_PATTERNS = {
    "netflix": {
        "sender_patterns": ["netflix.com", "account@netflix.com", "@netflix"],
        "subject_patterns": ["payment", "subscription", "billing", "facture", "abonnement"],
        "body_patterns": ["netflix", "abonnement", "subscription"],
        "service_name": "Netflix"
    },
    "spotify": {
        "sender_patterns": ["spotify.com", "no-reply@spotify.com", "@spotify"],
        "subject_patterns": ["payment", "premium", "subscription", "facture", "abonnement"],
        "body_patterns": ["spotify", "premium", "abonnement"],
        "service_name": "Spotify"
    },
    "amazon_prime": {
        "sender_patterns": ["amazon.com", "prime@amazon", "@amazon"],
        "subject_patterns": ["prime membership", "amazon prime", "abonnement prime"],
        "body_patterns": ["amazon prime", "membership", "abonnement"],
        "service_name": "Amazon Prime"
    },
    "youtube": {
        "sender_patterns": ["youtube.com", "noreply@youtube.com", "@youtube"],
        "subject_patterns": ["premium", "subscription", "abonnement", "facture"],
        "body_patterns": ["youtube", "premium", "abonnement"],
        "service_name": "YouTube Premium"
    },
    "disney_plus": {
        "sender_patterns": ["disneyplus.com", "disney+", "@disney"],
        "subject_patterns": ["payment", "subscription", "facture", "abonnement"],
        "body_patterns": ["disney", "abonnement", "subscription"],
        "service_name": "Disney+"
    },
    "apple": {
        "sender_patterns": ["apple.com", "itunes.com", "@apple"],
        "subject_patterns": ["receipt", "subscription", "facture", "reçu", "abonnement"],
        "body_patterns": ["apple", "itunes", "app store", "abonnement"],
        "service_name": "Apple Services"
    },
    "google": {
        "sender_patterns": ["google.com", "payments-noreply@google.com", "@google"],
        "subject_patterns": ["payment", "google one", "youtube premium", "facture", "abonnement"],
        "body_patterns": ["google", "youtube", "abonnement"],
        "service_name": "Google Services"
    },
    "microsoft": {
        "sender_patterns": ["microsoft.com", "msft@microsoft.com", "@microsoft"],
        "subject_patterns": ["office 365", "microsoft 365", "subscription", "abonnement"],
        "body_patterns": ["microsoft", "office", "365", "abonnement"],
        "service_name": "Microsoft 365"
    }
}

# Mots-clés pour la détection générique
SUBSCRIPTION_KEYWORDS = [
    "abonnement", "souscription", "mensuel", "annuel", "facturation", 
    "prélèvement", "renouvellement", "essai gratuit", "période d'essai",
    "subscription", "billing", "payment", "recurring", "monthly", "yearly",
    "trial", "premium", "membership", "plan", "service", "auto-renewal"
]

class HTTPGmailManager:
    """Gestionnaire Gmail utilisant uniquement des requêtes HTTP"""
    
    def __init__(self, access_token: str, user_email: str):
        self.access_token = access_token
        self.user_email = user_email
        self.base_url = "https://gmail.googleapis.com/gmail/v1/users/me"
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """Tester la connexion à l'API Gmail"""
        try:
            response = requests.get(f"{self.base_url}/profile", headers=self.headers)
            
            if response.status_code == 200:
                profile = response.json()
                return {
                    "success": True,
                    "email": profile.get('emailAddress'),
                    "messages_total": profile.get('messagesTotal', 0),
                    "threads_total": profile.get('threadsTotal', 0)
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                    "status_code": response.status_code
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "status_code": None
            }
    
    def search_subscription_emails(self, days_back: int = 90) -> List[Dict[str, Any]]:
        """Rechercher les emails d'abonnement"""
        try:
            # Construire la requête de recherche
            search_query = self._build_search_query(days_back)
            encoded_query = urllib.parse.quote(search_query)
            
            # Rechercher les messages
            url = f"{self.base_url}/messages?q={encoded_query}&maxResults=50"
            response = requests.get(url, headers=self.headers)
            
            if response.status_code != 200:
                print(f"Erreur lors de la recherche: {response.status_code} - {response.text}")
                return []
            
            messages = response.json().get('messages', [])
            print(f"Trouvé {len(messages)} messages pour {self.user_email}")
            
            emails_data = []
            
            # Récupérer les détails de chaque message
            for i, message in enumerate(messages[:30]):  # Limiter à 30 messages
                try:
                    print(f"Traitement du message {i+1}/{min(len(messages), 30)}")
                    
                    # Récupérer les détails du message
                    msg_url = f"{self.base_url}/messages/{message['id']}?format=full"
                    msg_response = requests.get(msg_url, headers=self.headers)
                    
                    if msg_response.status_code == 200:
                        msg_data = msg_response.json()
                        email_info = self._parse_message(msg_data)
                        if email_info:
                            emails_data.append(email_info)
                    else:
                        print(f"Erreur pour le message {message['id']}: {msg_response.status_code}")
                        
                except Exception as e:
                    print(f"Erreur lors du traitement du message {message['id']}: {e}")
                    continue
            
            return emails_data
            
        except Exception as e:
            print(f"Erreur générale lors de la recherche: {e}")
            return []
    
    def _build_search_query(self, days_back: int) -> str:
        """Construire la requête de recherche Gmail"""
        date_limit = (datetime.now() - timedelta(days=days_back)).strftime("%Y/%m/%d")
        
        # Recherche plus ciblée avec des termes spécifiques
        keywords = [
            "subscription", "abonnement", "billing", "facture", 
            "payment", "paiement", "premium", "membership",
            "netflix", "spotify", "amazon prime", "youtube premium",
            "disney+", "apple", "microsoft", "google one"
        ]
        
        # Créer une requête OR pour tous les mots-clés
        keyword_query = " OR ".join([f'"{keyword}"' for keyword in keywords])
        query = f"after:{date_limit} ({keyword_query})"
        
        return query
    
    def _parse_message(self, message_data: dict) -> Optional[Dict[str, Any]]:
        """Parser un message Gmail"""
        try:
            headers = message_data.get('payload', {}).get('headers', [])
            
            subject = ""
            from_email = ""
            date_str = ""
            
            for header in headers:
                name = header.get('name', '').lower()
                value = header.get('value', '')
                
                if name == 'subject':
                    subject = value
                elif name == 'from':
                    from_email = value
                elif name == 'date':
                    date_str = value
            
            body = self._extract_body(message_data.get('payload', {}))
            
            return {
                "subject": subject,
                "from": from_email,
                "date": date_str,
                "body": body[:1500] if body else "",  # Limiter la taille
                "message_id": message_data.get('id')
            }
            
        except Exception as e:
            print(f"Erreur de parsing du message: {e}")
            return None
    
    def _extract_body(self, payload: dict) -> str:
        """Extraire le corps d'un message"""
        body = ""
        
        try:
            if 'parts' in payload:
                for part in payload['parts']:
                    if part.get('mimeType') == 'text/plain':
                        data = part.get('body', {}).get('data')
                        if data:
                            try:
                                # Ajouter du padding si nécessaire
                                padded_data = data + '=' * (-len(data) % 4)
                                body = base64.urlsafe_b64decode(padded_data).decode('utf-8', errors='ignore')
                                break
                            except Exception:
                                continue
                    elif part.get('mimeType') == 'text/html' and not body:
                        data = part.get('body', {}).get('data')
                        if data:
                            try:
                                padded_data = data + '=' * (-len(data) % 4)
                                body = base64.urlsafe_b64decode(padded_data).decode('utf-8', errors='ignore')
                            except Exception:
                                continue
            else:
                if payload.get('mimeType') in ['text/plain', 'text/html']:
                    data = payload.get('body', {}).get('data')
                    if data:
                        try:
                            padded_data = data + '=' * (-len(data) % 4)
                            body = base64.urlsafe_b64decode(padded_data).decode('utf-8', errors='ignore')
                        except Exception:
                            pass
                            
        except Exception as e:
            print(f"Erreur lors de l'extraction du body: {e}")
        
        return body

class SubscriptionAnalyzer:
    """Classe pour analyser et détecter les abonnements"""
    
    @staticmethod
    def detect_subscriptions(emails: List[Dict[str, Any]], user_email: str) -> List[Subscription]:
        """Détecter les abonnements dans une liste d'emails"""
        subscriptions = {}
        
        for email_data in emails:
            subscription = SubscriptionAnalyzer._analyze_email(email_data, user_email)
            if subscription:
                # Éviter les doublons en utilisant le nom du service comme clé
                key = subscription.service_name.lower()
                if key not in subscriptions:
                    subscriptions[key] = subscription
                else:
                    # Garder celui avec le plus d'informations
                    existing = subscriptions[key]
                    if subscription.amount and not existing.amount:
                        subscriptions[key] = subscription
                        
        return list(subscriptions.values())
    
    @staticmethod
    def _analyze_email(email_data: Dict[str, Any], user_email: str) -> Optional[Subscription]:
        """Analyser un email pour détecter un abonnement"""
        from_email = email_data.get("from", "").lower()
        subject = email_data.get("subject", "").lower()
        body = email_data.get("body", "").lower()
        full_text = f"{from_email} {subject} {body}"
        
        if not SubscriptionAnalyzer._is_subscription_email(full_text):
            return None
        
        # Vérifier chaque pattern d'abonnement spécifique
        for service_key, patterns in SUBSCRIPTION_PATTERNS.items():
            sender_match = any(pattern.lower() in from_email for pattern in patterns["sender_patterns"])
            subject_match = any(pattern.lower() in subject for pattern in patterns["subject_patterns"])
            body_match = any(pattern.lower() in body for pattern in patterns.get("body_patterns", []))
            
            if sender_match or subject_match or body_match:
                amount, currency = SubscriptionAnalyzer._extract_amount(body + " " + subject)
                billing_cycle = SubscriptionAnalyzer._extract_billing_cycle(body + " " + subject)
                
                return Subscription(
                    service_name=patterns["service_name"],
                    amount=amount,
                    currency=currency,
                    billing_cycle=billing_cycle,
                    email_from=email_data.get("from", ""),
                    detected_date=email_data.get("date", ""),
                    status="active",
                    user_email=user_email
                )
        
        # Détection générique
        service_name = SubscriptionAnalyzer._extract_service_name(from_email)
        if service_name:
            amount, currency = SubscriptionAnalyzer._extract_amount(body + " " + subject)
            billing_cycle = SubscriptionAnalyzer._extract_billing_cycle(body + " " + subject)
            
            return Subscription(
                service_name=service_name,
                amount=amount,
                currency=currency,
                billing_cycle=billing_cycle,
                email_from=email_data.get("from", ""),
                detected_date=email_data.get("date", ""),
                status="active",
                user_email=user_email
            )
        
        return None
    
    @staticmethod
    def _is_subscription_email(text: str) -> bool:
        """Vérifier si l'email concerne un abonnement"""
        return any(keyword.lower() in text.lower() for keyword in SUBSCRIPTION_KEYWORDS)
    
    @staticmethod
    def _extract_amount(text: str) -> tuple[Optional[float], Optional[str]]:
        """Extraire le montant et la devise du texte"""
        patterns = [
            r'(\d+[.,]\d{2})\s*(€|EUR|eur|euros?)',
            r'(\d+[.,]\d{2})\s*(\$|USD|usd|dollars?)',
            r'(\d+[.,]\d{2})\s*(£|GBP|gbp|pounds?)',
            r'€\s*(\d+[.,]\d{2})',
            r'\$\s*(\d+[.,]\d{2})',
            r'£\s*(\d+[.,]\d{2})',
            r'(\d+[.,]\d{2})\s*EUR',
            r'(\d+[.,]\d{2})\s*USD',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                try:
                    amount_str = match.group(1)
                    amount_str = amount_str.replace(',', '.')
                    amount = float(amount_str)
                    
                    match_text = match.group(0).upper()
                    if '€' in match_text or 'EUR' in match_text:
                        return amount, 'EUR'
                    elif '$' in match_text or 'USD' in match_text:
                        return amount, 'USD'
                    elif '£' in match_text or 'GBP' in match_text:
                        return amount, 'GBP'
                    else:
                        return amount, 'EUR'  # Par défaut
                except ValueError:
                    continue
                    
        return None, None
    
    @staticmethod
    def _extract_billing_cycle(text: str) -> Optional[str]:
        """Extraire la période de facturation"""
        text = text.lower()
        
        if any(word in text for word in ["monthly", "month", "mensuel", "mois", "/mois", "per month", "mth"]):
            return "monthly"
        elif any(word in text for word in ["yearly", "annual", "year", "annuel", "an", "/an", "per year", "yr"]):
            return "yearly"
        elif any(word in text for word in ["weekly", "week", "hebdomadaire", "semaine", "/semaine", "wk"]):
            return "weekly"
        elif any(word in text for word in ["quarterly", "trimestre", "/trimestre", "3 months"]):
            return "quarterly"
            
        return "monthly"  # Par défaut
    
    @staticmethod
    def _extract_service_name(from_email: str) -> Optional[str]:
        """Extraire le nom du service depuis l'email de l'expéditeur"""
        from_email = from_email.lower()
        
        # Rechercher le domaine
        match = re.search(r'@([a-zA-Z0-9.-]+)', from_email)
        if match:
            domain = match.group(1)
            # Nettoyer le domaine
            service_name = domain.replace('.com', '').replace('.fr', '').replace('.net', '')
            service_name = service_name.replace('.org', '').replace('.co', '').replace('.io', '')
            
            # Prendre la partie principale du domaine
            if '.' in service_name:
                service_name = service_name.split('.')[0]
                
            # Filtrer les domaines génériques
            generic_domains = ['noreply', 'no-reply', 'support', 'info', 'contact', 'mail', 'email']
            if service_name not in generic_domains and len(service_name) > 2:
                return service_name.capitalize()
                
        return None

class SubscriptionService:
    """Service pour gérer la logique métier des abonnements"""
    
    @staticmethod
    def get_user_subscriptions(access_token: str, user_email: str, user_name: str, days_back: int = 90) -> Dict[str, Any]:
        """Récupérer les abonnements de l'utilisateur"""
        
        # Créer le gestionnaire Gmail HTTP
        gmail_manager = HTTPGmailManager(access_token, user_email)
        
        # Tester la connexion d'abord
        connection_test = gmail_manager.test_connection()
        if not connection_test["success"]:
            return {
                "success": False,
                "message": f"Impossible de se connecter à Gmail: {connection_test.get('error', 'Erreur inconnue')}",
                "subscriptions": [],
                "debug_info": {
                    "connection_test": connection_test,
                    "user_email": user_email,
                    "has_token": bool(access_token)
                }
            }
        
        try:
            print(f"Connexion Gmail réussie pour {user_email}")
            print(f"Messages total: {connection_test.get('messages_total', 'N/A')}")
            
            # Rechercher les emails
            emails = gmail_manager.search_subscription_emails(days_back)
            print(f"Emails trouvés: {len(emails)}")
            
            # Analyser les abonnements
            subscriptions = SubscriptionAnalyzer.detect_subscriptions(emails, user_email)
            print(f"Abonnements détectés: {len(subscriptions)}")
            
            # Calculer les statistiques
            total_monthly = 0
            currencies_found = set()
            
            for sub in subscriptions:
                if sub.amount and sub.currency:
                    currencies_found.add(sub.currency)
                    if sub.billing_cycle == "monthly":
                        total_monthly += sub.amount
                    elif sub.billing_cycle == "yearly":
                        total_monthly += sub.amount / 12
                    elif sub.billing_cycle == "weekly":
                        total_monthly += sub.amount * 4
                    elif sub.billing_cycle == "quarterly":
                        total_monthly += sub.amount / 3
            
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
                "message": f"Analyse terminée pour {user_name}",
                "user": {
                    "email": user_email,
                    "name": user_name
                },
                "subscriptions": subscription_list,
                "statistics": {
                    "total_subscriptions": len(subscriptions),
                    "estimated_monthly_cost": round(total_monthly, 2),
                    "currencies_detected": list(currencies_found),
                    "emails_analyzed": len(emails),
                    "gmail_messages_total": connection_test.get('messages_total', 0)
                }
            }
            
        except Exception as e:
            return {
                "success": False,
                "message": f"Erreur lors de l'analyse: {str(e)}",
                "user": {
                    "email": user_email,
                    "name": user_name
                },
                "subscriptions": [],
                "debug_info": {
                    "error_details": str(e),
                    "connection_test": connection_test
                }
            }

# Tools MCP

@mcp.tool
async def get_user_info() -> Dict[str, Any]:
    """Obtenir les informations de l'utilisateur Google connecté"""
    try:
        token = get_access_token()
        
        return {
            "google_id": token.claims.get("sub"),
            "email": token.claims.get("email"),
            "name": token.claims.get("name"),
            "picture": token.claims.get("picture"),
            "locale": token.claims.get("locale"),
            "authenticated": True,
            "token_info": {
                "token_available": hasattr(token, 'token') and token.token is not None,
                "token_length": len(token.token) if hasattr(token, 'token') and token.token else 0
            }
        }
    except Exception as e:
        return {
            "error": f"Erreur: {str(e)}",
            "authenticated": False
        }

@mcp.tool(
    title="Test Gmail Connection",
    description="Tester la connexion Gmail"
)
async def test_gmail_connection() -> Dict[str, Any]:
    """Tester la connexion Gmail"""
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        
        if not user_email:
            return {"success": False, "error": "Email utilisateur non trouvé"}
        
        if not hasattr(token, 'token') or not token.token:
            return {"success": False, "error": "Token d'accès non trouvé"}
        
        # Créer le gestionnaire et tester
        gmail_manager = HTTPGmailManager(token.token, user_email)
        result = gmail_manager.test_connection()
        
        return {
            "success": result["success"],
            "user_email": user_email,
            "connection_details": result,
            "token_length": len(token.token)
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

@mcp.tool(
    title="Fetch My Subscriptions",
    description="Récupérer et analyser vos abonnements depuis Gmail"
)
async def fetch_my_subscriptions(
    days_back: int = Field(description="Nombre de jours à analyser (max 180)", default=90)
) -> Dict[str, Any]:
    """Récupérer les abonnements de l'utilisateur connecté"""
    
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        user_name = token.claims.get("name", "Utilisateur")
        
        if not user_email:
            return {
                "success": False,
                "message": "Email utilisateur non trouvé",
                "subscriptions": []
            }
        
        if not hasattr(token, 'token') or not token.token:
            return {
                "success": False,
                "message": "Token d'accès non trouvé",
                "subscriptions": []
            }
        
        # Limiter la période d'analyse
        days_back = min(days_back, 180)
        
        return SubscriptionService.get_user_subscriptions(
            token.token, user_email, user_name, days_back
        )
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Erreur: {str(e)}",
            "subscriptions": []
        }

@mcp.tool(
    title="Get My Subscription Summary", 
    description="Résumé textuel de vos abonnements"
)
async def get_my_subscription_summary(
    days_back: int = Field(description="Nombre de jours à analyser", default=90)
) -> str:
    """Générer un résumé des abonnements"""
    
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        user_name = token.claims.get("name", "Utilisateur")
        
        if not user_email or not hasattr(token, 'token') or not token.token:
            return "❌ Erreur: Informations d'authentification manquantes"
        
        # Récupérer les données
        result = SubscriptionService.get_user_subscriptions(
            token.token, user_email, user_name, days_back
        )
        
        if not result["success"]:
            return f"❌ Erreur: {result['message']}"
        
        # Générer le résumé
        user = result["user"]
        subscriptions = result["subscriptions"]
        stats = result["statistics"]
        
        if not subscriptions:
            return f"🔍 Aucun abonnement détecté dans les emails de {user['name']} ({user['email']})\n📧 {stats['emails_analyzed']} emails analysés sur {days_back} jours."
        
        summary = f"📊 RÉSUMÉ DES ABONNEMENTS DE {user['name'].upper()}\n"
        summary += f"{'='*60}\n\n"
        summary += f"📧 Compte Gmail: {user['email']}\n"
        summary += f"📈 Abonnements détectés: {stats['total_subscriptions']}\n"
        summary += f"💰 Coût mensuel estimé: {stats['estimated_monthly_cost']} EUR\n"
        summary += f"💱 Devises: {', '.join(stats['currencies_detected']) if stats['currencies_detected'] else 'Non détectées'}\n"
        summary += f"📧 Emails analysés: {stats['emails_analyzed']}\n"
        summary += f"📅 Période: {days_back} derniers jours\n\n"
        
        summary += "📋 DÉTAILS DES ABONNEMENTS:\n"
        summary += f"{'='*60}\n"
        
        # Trier par montant
        sorted_subs = sorted([s for s in subscriptions if s['amount']], 
                           key=lambda x: x['amount'] or 0, reverse=True)
        
        for sub in sorted_subs:
            summary += f"\n✅ {sub['service']}\n"
            if sub['amount']:
                cycle = f" ({sub['billing_cycle']})" if sub['billing_cycle'] else ""
                summary += f"  💰 {sub['amount']:.2f} {sub['currency'] or 'EUR'}{cycle}\n"
            
            if sub['detected_from']:
                summary += f"  📧 De: {sub['detected_from'][:50]}{'...' if len(sub['detected_from']) > 50 else ''}\n"
        
        # Services sans montant détecté
        no_amount = [s for s in subscriptions if not s['amount']]
        if no_amount:
            summary += f"\n🔍 AUTRES SERVICES DÉTECTÉS ({len(no_amount)}):\n"
            for sub in no_amount:
                summary += f"  • {sub['service']} - {sub['detected_from'][:40]}{'...' if len(sub['detected_from']) > 40 else ''}\n"
        
        return summary
        
    except Exception as e:
        return f"❌ Erreur dans get_my_subscription_summary: {str(e)}"

@mcp.tool(
    title="Export My Subscriptions",
    description="Exporter vos abonnements au format JSON"
)
async def export_my_subscriptions(
    days_back: int = Field(description="Nombre de jours à analyser", default=90)
) -> str:
    """Exporter les abonnements au format JSON"""
    
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        user_name = token.claims.get("name", "Utilisateur")
        
        if not user_email or not hasattr(token, 'token') or not token.token:
            return json.dumps({"error": "Informations d'authentification manquantes"}, indent=2)
        
        # Récupérer les données
        result = SubscriptionService.get_user_subscriptions(
            token.token, user_email, user_name, days_back
        )
        
        if not result["success"]:
            return json.dumps({"error": result["message"]}, indent=2)
        
        # Préparer l'export
        export_data = {
            "export_metadata": {
                "export_date": datetime.now().isoformat(),
                "export_version": "2.0",
                "days_analyzed": days_back
            },
            "user_info": result["user"],
            "analysis_statistics": result["statistics"],
            "subscriptions": result["subscriptions"],
            "summary": {
                "total_services": len(result["subscriptions"]),
                "services_with_pricing": len([s for s in result["subscriptions"] if s["amount"]]),
                "estimated_yearly_cost": result["statistics"]["estimated_monthly_cost"] * 12
            }
        }
        
        return json.dumps(export_data, indent=2, ensure_ascii=False)
        
    except Exception as e:
        return json.dumps({"error": f"Erreur dans export_my_subscriptions: {str(e)}"}, indent=2)

@mcp.tool(
    title="Search Specific Service",
    description="Rechercher un service spécifique dans vos emails"
)
async def search_specific_service(
    service_name: str = Field(description="Nom du service à rechercher (ex: Netflix, Spotify)"),
    days_back: int = Field(description="Nombre de jours à analyser", default=90)
) -> Dict[str, Any]:
    """Rechercher un service spécifique dans les emails"""
    
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        
        if not user_email or not hasattr(token, 'token') or not token.token:
            return {
                "success": False,
                "message": "Informations d'authentification manquantes"
            }
        
        # Créer le gestionnaire Gmail
        gmail_manager = HTTPGmailManager(token.token, user_email)
        
        # Tester la connexion
        connection_test = gmail_manager.test_connection()
        if not connection_test["success"]:
            return {
                "success": False,
                "message": f"Impossible de se connecter à Gmail: {connection_test.get('error')}"
            }
        
        # Recherche ciblée
        date_limit = (datetime.now() - timedelta(days=days_back)).strftime("%Y/%m/%d")
        search_query = f'after:{date_limit} "{service_name.lower()}"'
        encoded_query = urllib.parse.quote(search_query)
        
        url = f"{gmail_manager.base_url}/messages?q={encoded_query}&maxResults=20"
        response = requests.get(url, headers=gmail_manager.headers)
        
        if response.status_code != 200:
            return {
                "success": False,
                "message": f"Erreur de recherche: {response.status_code}"
            }
        
        messages = response.json().get('messages', [])
        
        # Analyser les messages trouvés
        results = []
        for message in messages[:10]:  # Limiter à 10 résultats
            try:
                msg_url = f"{gmail_manager.base_url}/messages/{message['id']}?format=full"
                msg_response = requests.get(msg_url, headers=gmail_manager.headers)
                
                if msg_response.status_code == 200:
                    msg_data = msg_response.json()
                    email_info = gmail_manager._parse_message(msg_data)
                    if email_info:
                        # Analyser pour les détails d'abonnement
                        subscription = SubscriptionAnalyzer._analyze_email(email_info, user_email)
                        results.append({
                            "subject": email_info["subject"],
                            "from": email_info["from"],
                            "date": email_info["date"],
                            "subscription_detected": subscription is not None,
                            "amount": subscription.amount if subscription else None,
                            "currency": subscription.currency if subscription else None,
                            "billing_cycle": subscription.billing_cycle if subscription else None
                        })
            except Exception as e:
                continue
        
        return {
            "success": True,
            "service_searched": service_name,
            "messages_found": len(messages),
            "results_analyzed": len(results),
            "results": results
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Erreur: {str(e)}"
        }

@mcp.tool(
    title="Get Subscription Statistics",
    description="Obtenir des statistiques détaillées sur vos abonnements"
)
async def get_subscription_statistics(
    days_back: int = Field(description="Nombre de jours à analyser", default=90)
) -> Dict[str, Any]:
    """Obtenir des statistiques détaillées sur les abonnements"""
    
    try:
        token = get_access_token()
        user_email = token.claims.get("email")
        user_name = token.claims.get("name", "Utilisateur")
        
        if not user_email or not hasattr(token, 'token') or not token.token:
            return {
                "success": False,
                "message": "Informations d'authentification manquantes"
            }
        
        # Récupérer les données
        result = SubscriptionService.get_user_subscriptions(
            token.token, user_email, user_name, days_back
        )
        
        if not result["success"]:
            return {
                "success": False,
                "message": result["message"]
            }
        
        subscriptions = result["subscriptions"]
        
        # Calculer des statistiques avancées
        by_currency = {}
        by_billing_cycle = {}
        by_amount_range = {"0-10": 0, "10-25": 0, "25-50": 0, "50+": 0}
        services_by_category = {}
        
        total_yearly_cost = 0
        
        for sub in subscriptions:
            # Par devise
            currency = sub["currency"] or "Unknown"
            if currency not in by_currency:
                by_currency[currency] = {"count": 0, "total": 0}
            by_currency[currency]["count"] += 1
            
            # Par cycle de facturation
            cycle = sub["billing_cycle"] or "Unknown"
            if cycle not in by_billing_cycle:
                by_billing_cycle[cycle] = {"count": 0, "total": 0}
            by_billing_cycle[cycle]["count"] += 1
            
            # Calculs avec montants
            if sub["amount"]:
                by_currency[currency]["total"] += sub["amount"]
                by_billing_cycle[cycle]["total"] += sub["amount"]
                
                # Coût annuel estimé
                if sub["billing_cycle"] == "monthly":
                    total_yearly_cost += sub["amount"] * 12
                elif sub["billing_cycle"] == "yearly":
                    total_yearly_cost += sub["amount"]
                elif sub["billing_cycle"] == "weekly":
                    total_yearly_cost += sub["amount"] * 52
                elif sub["billing_cycle"] == "quarterly":
                    total_yearly_cost += sub["amount"] * 4
                
                # Par tranche de prix (mensuel équivalent)
                monthly_equiv = sub["amount"]
                if sub["billing_cycle"] == "yearly":
                    monthly_equiv = sub["amount"] / 12
                elif sub["billing_cycle"] == "weekly":
                    monthly_equiv = sub["amount"] * 4
                elif sub["billing_cycle"] == "quarterly":
                    monthly_equiv = sub["amount"] / 3
                
                if monthly_equiv < 10:
                    by_amount_range["0-10"] += 1
                elif monthly_equiv < 25:
                    by_amount_range["10-25"] += 1
                elif monthly_equiv < 50:
                    by_amount_range["25-50"] += 1
                else:
                    by_amount_range["50+"] += 1
            
            # Catégorisation par service
            service = sub["service"].lower()
            if "netflix" in service or "disney" in service or "prime" in service:
                category = "Streaming Vidéo"
            elif "spotify" in service or "apple music" in service or "youtube music" in service:
                category = "Streaming Audio"
            elif "google" in service or "microsoft" in service or "apple" in service:
                category = "Services Tech"
            else:
                category = "Autres"
            
            if category not in services_by_category:
                services_by_category[category] = 0
            services_by_category[category] += 1
        
        return {
            "success": True,
            "user": result["user"],
            "period_analyzed": f"{days_back} jours",
            "basic_stats": result["statistics"],
            "advanced_statistics": {
                "total_yearly_cost_estimated": round(total_yearly_cost, 2),
                "average_cost_per_service": round(total_yearly_cost / len([s for s in subscriptions if s["amount"]]), 2) if subscriptions else 0,
                "breakdown_by_currency": by_currency,
                "breakdown_by_billing_cycle": by_billing_cycle,
                "breakdown_by_amount_range": by_amount_range,
                "breakdown_by_category": services_by_category
            },
            "recommendations": [
                "Considérez regrouper vos services de streaming pour économiser",
                "Vérifiez si vous utilisez vraiment tous vos abonnements",
                "Regardez les offres annuelles qui peuvent être plus économiques",
                f"Votre coût annuel estimé de {round(total_yearly_cost, 2)} EUR représente {round(total_yearly_cost/12, 2)} EUR/mois"
            ]
        }
        
    except Exception as e:
        return {
            "success": False,
            "message": f"Erreur: {str(e)}"
        }

@mcp.resource(
    uri="subscription://user/{user_email}",
    description="Ressource pour les abonnements d'un utilisateur spécifique",
    name="User Subscription Resource"
)
async def get_user_subscription_resource(user_email: str) -> str:
    """Ressource pour obtenir les abonnements d'un utilisateur"""
    try:
        token = get_access_token()
        current_user_email = token.claims.get("email")
        
        if current_user_email != user_email:
            return f"Accès non autorisé pour {user_email}"
        
        return f"Ressource d'abonnements pour {user_email}"
        
    except Exception as e:
        return f"Erreur: {str(e)}"

@mcp.prompt("analyze_subscription_costs")
async def analyze_subscription_costs_prompt(
    focus: str = Field(description="Focus: monthly, yearly, ou optimization", default="monthly")
) -> str:
    """Prompt d'analyse des coûts d'abonnement"""
    
    try:
        token = get_access_token()
        user_name = token.claims.get("name", "l'utilisateur")
        
        if focus == "monthly":
            return f"Analysez les coûts mensuels des abonnements de {user_name}. Identifiez les services les plus coûteux et proposez des moyens de réduire les dépenses mensuelles."
        elif focus == "yearly":
            return f"Calculez et analysez les coûts annuels des abonnements de {user_name}. Montrez l'impact sur le budget annuel et identifiez les opportunités d'économies à long terme."
        elif focus == "optimization":
            return f"Proposez une stratégie complète d'optimisation des abonnements de {user_name}. Incluez des alternatives moins chères, des regroupements possibles et des recommandations personnalisées."
        else:
            return f"Analysez globalement tous les aspects financiers des abonnements de {user_name}."
            
    except Exception as e:
        return f"Erreur: {str(e)}"

if __name__ == "__main__":
    print("🚀 Démarrage du serveur MCP Subscription Manager (HTTP uniquement)...")
    print(f"🔑 Client ID: {GOOGLE_CLIENT_ID}")
    print(f"🌐 URL de base: {BASE_URL}")
    print("✅ Mode HTTP uniquement - Pas de dépendances Google requises")
    mcp.run(transport="http")