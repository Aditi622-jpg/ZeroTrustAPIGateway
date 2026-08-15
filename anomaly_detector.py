from collections import defaultdict

from sklearn.ensemble import IsolationForest

from database import SessionLocal
from models import APIAnalytics, AnomalyResult, AuditLog


def run_anomaly_detection():
    db = SessionLocal()

    try:
        user_statistics = defaultdict(
            lambda: {
                "total_requests": 0,
                "denied_requests": 0,
                "failed_logins": 0,
                "rate_limited_requests": 0,
                "endpoints": set()
            }
        )

        api_records = db.query(APIAnalytics).all()

        for record in api_records:
            username = record.username or "Anonymous"

            statistics = user_statistics[username]

            statistics["total_requests"] += 1

            if record.status == "Denied":
                statistics["denied_requests"] += 1

            if record.status == "Rate Limited":
                statistics["rate_limited_requests"] += 1

            if record.endpoint:
                statistics["endpoints"].add(record.endpoint)

        failed_login_records = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "User Login",
                AuditLog.status == "Failed"
            )
            .all()
        )

        for record in failed_login_records:
            username = record.username or "Anonymous"

            user_statistics[username]["failed_logins"] += 1

        usernames = list(user_statistics.keys())

        if len(usernames) < 3:
            return {
                "success": False,
                "message": (
                    "At least 3 users with activity are required "
                    "to run anomaly detection."
                )
            }

        feature_rows = []

        for username in usernames:
            statistics = user_statistics[username]

            feature_rows.append([
                statistics["total_requests"],
                statistics["denied_requests"],
                statistics["failed_logins"],
                statistics["rate_limited_requests"],
                len(statistics["endpoints"])
            ])

        model = IsolationForest(
            n_estimators=100,
            contamination="auto",
            random_state=42
        )

        predictions = model.fit_predict(feature_rows)
        scores = model.decision_function(feature_rows)

        db.query(AnomalyResult).delete()

        for index, username in enumerate(usernames):
            statistics = user_statistics[username]

            result = (
                "Anomaly"
                if predictions[index] == -1
                else "Normal"
            )

            anomaly_result = AnomalyResult(
                username=username,
                total_requests=statistics["total_requests"],
                denied_requests=statistics["denied_requests"],
                failed_logins=statistics["failed_logins"],
                rate_limited_requests=(
                    statistics["rate_limited_requests"]
                ),
                unique_endpoints=len(statistics["endpoints"]),
                result=result,
                anomaly_score=str(
                    round(float(scores[index]), 4)
                )
            )

            db.add(anomaly_result)

        db.commit()

        anomaly_count = sum(
            1
            for prediction in predictions
            if prediction == -1
        )

        return {
            "success": True,
            "message": "Anomaly detection completed.",
            "analysed_users": len(usernames),
            "anomaly_count": anomaly_count
        }

    except Exception as error:
        db.rollback()

        return {
            "success": False,
            "message": str(error)
        }

    finally:
        db.close()