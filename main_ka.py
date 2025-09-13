# run_http.py
import logging
import uuid
from datetime import datetime
from typing import Optional, Dict, List

import uvicorn
from starlette.applications import Starlette
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from mcp.server.fastmcp import FastMCP

# --- briques métier locales (même dossier que ce fichier) ---
from connection import DatabaseManager
from analyzer import SubscriptionAnalyzer
from email_parser import EmailParser
from csv_parser import BankCSVParser

# Logging basique
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("subscription-http")

# 1) Instance MCP (transport HTTP streamable)
mcp = FastMCP("subscription-manager")

# Dépendances partagées
db = DatabaseManager()
analyzer = SubscriptionAnalyzer(db)
email_parser = EmailParser()
csv_parser = BankCSVParser()

# 2) Outils MCP
@mcp.tool()
async def scan_subscriptions(source: str, credentials: Optional[Dict] = None) -> Dict:
    try:
        subscriptions: List[Dict] = []
        if source == "email":
            mock_emails = [
                "Your Netflix subscription of €15.99 has been renewed",
                "Spotify Premium: €9.99 charged to your account",
                "Adobe Creative Cloud: Payment received €54.99",
                "Dropbox Plus: €11.99 monthly subscription",
                "GitHub Pro: $7 monthly payment confirmed",
            ]
            for email_content in mock_emails:
                parsed = email_parser.parse_email(email_content)
                if parsed:
                    subscriptions.append(parsed)
                    await db.add_subscription({
                        'name': parsed.get('service', 'Unknown'),
                        'cost': parsed.get('amount', 0),
                        'currency': parsed.get('currency', 'EUR'),
                        'billing_cycle': 'monthly',
                        'category': parsed.get('category', 'other'),
                        'status': 'active',
                        'start_date': datetime.now().isoformat(),
                    })
        elif source == "csv":
            if credentials and 'file_path' in credentials:
                patterns = csv_parser.parse_csv(
                    credentials['file_path'],
                    credentials.get('bank_format', 'generic')
                )
                subscriptions = patterns

        total_monthly = sum(
            s.get('amount', 0) for s in subscriptions if s.get('cycle') == 'monthly'
        )
        return {
            "success": True,
            "subscriptions_found": len(subscriptions),
            "subscriptions": subscriptions,
            "total_monthly": round(total_monthly, 2),
            "source": source,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        log.exception("scan_subscriptions failed")
        return {"success": False, "error": str(e), "subscriptions_found": 0}

@mcp.tool()
async def add_subscription(
    name: str, cost: float, cycle: str, category: str = "other", currency: str = "EUR"
) -> Dict:
    try:
        subscription_id = str(uuid.uuid4())
        subscription_data = {
            'id': subscription_id,
            'name': name,
            'cost': cost,
            'currency': currency,
            'billing_cycle': cycle,
            'category': category,
            'status': 'active',
            'start_date': datetime.now().isoformat(),
            'created_at': datetime.now().isoformat(),
        }
        await db.add_subscription(subscription_data)
        next_billing = analyzer.calculate_next_billing(cycle)
        return {
            "success": True,
            "subscription_id": subscription_id,
            "name": name,
            "cost": cost,
            "cycle": cycle,
            "category": category,
            "next_billing": next_billing,
            "message": f"Subscription '{name}' added successfully",
        }
    except Exception as e:
        log.exception("add_subscription failed")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def analyze_spending() -> Dict:
    try:
        subscriptions = await db.get_all_subscriptions()
        if not subscriptions:
            return {
                "success": True,
                "message": "No subscriptions found",
                "total_monthly": 0,
                "total_yearly": 0,
            }
        analysis = {
            "total_monthly": analyzer.calculate_monthly_spending(subscriptions),
            "total_yearly": 0,
            "by_category": {},
            "by_status": {},
            "most_expensive": None,
            "least_used": [],
            "subscription_count": len(subscriptions),
        }
        categories: Dict[str, Dict[str, float]] = {}
        for sub in subscriptions:
            cat = sub.get('category', 'other')
            categories.setdefault(cat, {'count': 0, 'total': 0.0})
            categories[cat]['count'] += 1
            categories[cat]['total'] += analyzer.normalize_to_monthly(
                sub.get('cost', 0), sub.get('billing_cycle', 'monthly')
            )
        analysis['by_category'] = categories
        analysis['total_yearly'] = round(analysis['total_monthly'] * 12, 2)

        me = max(subscriptions, key=lambda x: x.get('cost', 0), default=None)
        if me:
            analysis['most_expensive'] = {
                'name': me.get('name'),
                'cost': me.get('cost'),
                'cycle': me.get('billing_cycle'),
            }

        analysis['least_used'] = analyzer.find_unused_subscriptions(subscriptions)
        return {
            "success": True,
            "analysis": analysis,
            "currency": "EUR",
            "generated_at": datetime.now().isoformat(),
        }
    except Exception as e:
        log.exception("analyze_spending failed")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def get_recommendations() -> Dict:
    try:
        subscriptions = await db.get_all_subscriptions()
        if not subscriptions:
            return {"success": True, "recommendations": [], "potential_savings": 0}
        recommendations: List[Dict] = []
        total_savings = 0.0

        for dup in analyzer.find_duplicates(subscriptions):
            recommendations.append({
                "type": "duplicate",
                "severity": "high",
                "services": dup['services'],
                "action": f"Consider cancelling one of: {', '.join(dup['services'])}",
                "savings": dup['potential_saving'],
            })
            total_savings += dup['potential_saving']

        for service in analyzer.find_unused_subscriptions(subscriptions):
            recommendations.append({
                "type": "unused",
                "severity": "medium",
                "service": service['name'],
                "action": f"Cancel {service['name']} - not used for 60+ days",
                "savings": service['cost'],
            })
            total_savings += service['cost']

        alternatives = {
            "Adobe Creative Cloud": {"alternative": "Canva Pro", "savings": 43.00},
            "Dropbox Plus": {"alternative": "Google One", "savings": 10.00},
        }
        for sub in subscriptions:
            if sub.get('name') in alternatives:
                alt = alternatives[sub['name']]
                recommendations.append({
                    "type": "alternative",
                    "severity": "low",
                    "service": sub['name'],
                    "action": f"Switch to {alt['alternative']}",
                    "savings": alt['savings'],
                })
                total_savings += alt['savings']

        streaming = [s for s in subscriptions if s.get('category') == 'streaming']
        if len(streaming) > 2:
            est = len(streaming) * 5
            recommendations.append({
                "type": "bundle",
                "severity": "medium",
                "services": [s['name'] for s in streaming],
                "action": "Consider a streaming bundle package",
                "savings": est,
            })
            total_savings += est

        return {
            "success": True,
            "recommendations": recommendations[:5],
            "potential_monthly_savings": round(total_savings, 2),
            "potential_yearly_savings": round(total_savings * 12, 2),
            "total_recommendations": len(recommendations),
        }
    except Exception as e:
        log.exception("get_recommendations failed")
        return {"success": False, "error": str(e)}

@mcp.tool()
async def cancel_subscription(subscription_id: str, generate_email: bool = True) -> Dict:
    try:
        subscription = await db.get_subscription(subscription_id)
        if not subscription:
            all_subs = await db.get_all_subscriptions()
            subscription = next(
                (s for s in all_subs if s.get('name', '').lower() == subscription_id.lower()),
                None
            )
        if not subscription:
            return {"success": False, "error": f"Subscription '{subscription_id}' not found"}

        result = {
            "success": True,
            "subscription": subscription['name'],
            "status": "cancellation_prepared",
        }

        if generate_email:
            email_template = f"""Subject: Cancellation Request - {subscription['name']} Subscription

Dear {subscription['name']} Support Team,

I would like to cancel my subscription effective immediately.

Account Information:
- Service: {subscription['name']}
- Current Plan: {subscription.get('billing_cycle','monthly').title()}
- Monthly Cost: {subscription.get('currency','€')}{subscription.get('cost',0)}

Please confirm the cancellation and the last billing date.

Thank you for your service.

Best regards,
[Your Name]"""
            result['email_template'] = email_template

        await db.update_subscription(
            subscription.get('id', subscription_id),
            {'status': 'cancelled', 'cancelled_at': datetime.now().isoformat()}
        )
        alternatives = analyzer.find_alternatives(subscription['name'])
        if alternatives:
            result['alternatives'] = alternatives
        result['next_steps'] = [
            f"1. Send the cancellation email to {subscription['name']} support",
            "2. Check for any cancellation fees or notice period",
            "3. Download any data you want to keep",
            "4. Remove payment method from their platform",
            "5. Keep the cancellation confirmation for your records",
        ]
        return result
    except Exception as e:
        log.exception("cancel_subscription failed")
        return {"success": False, "error": str(e)}

# 3) App HTTP + /health
async def health(_):
    return JSONResponse({"ok": True, "service": "subscription-manager"})

starlette_app = Starlette(routes=[
    Route("/health", health),
    Mount("/", app=mcp.streamable_http_app()),
])

starlette_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],              # restreins en prod
    allow_methods=["GET","POST","DELETE"],
    expose_headers=["Mcp-Session-Id"],  # requis pour certains clients web MCP
)

if _name_ == "_main_":
    uvicorn.run(starlette_app, host="0.0.0.0", port=8000)