from collections import defaultdict

import numpy as np

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
    roc_curve,
    precision_recall_curve
)

from database import SessionLocal
from models import APIAnalytics, AnomalyResult, AuditLog


# ============================================================
# 1. RISK SCORING
# ============================================================

def calculate_risk_score(statistics, prediction, model_score):

    risk_score = 0
    reasons = []

    failed_logins = statistics["failed_logins"]
    denied_requests = statistics["denied_requests"]
    rate_limited_requests = statistics["rate_limited_requests"]
    total_requests = statistics["total_requests"]
    unique_endpoints = statistics["unique_endpoints"]

    # Failed login analysis
    if failed_logins >= 10:
        risk_score += 30
        reasons.append("Very high number of failed login attempts")
    elif failed_logins >= 5:
        risk_score += 20
        reasons.append("Multiple failed login attempts")
    elif failed_logins >= 2:
        risk_score += 10
        reasons.append("Repeated failed login attempts")

    # Denied request analysis
    if denied_requests >= 20:
        risk_score += 25
        reasons.append("Very high number of denied requests")
    elif denied_requests >= 10:
        risk_score += 15
        reasons.append("Multiple denied requests")
    elif denied_requests >= 5:
        risk_score += 8
        reasons.append("Repeated denied requests")

    # Rate limiting analysis
    if rate_limited_requests >= 10:
        risk_score += 25
        reasons.append("Excessive rate-limited requests")
    elif rate_limited_requests >= 5:
        risk_score += 15
        reasons.append("Multiple rate-limit violations")
    elif rate_limited_requests >= 2:
        risk_score += 8
        reasons.append("Repeated rate-limit violations")

    # Request volume analysis
    if total_requests >= 500:
        risk_score += 15
        reasons.append("Unusually high API request volume")
    elif total_requests >= 200:
        risk_score += 10
        reasons.append("High API request volume")

    # Endpoint access analysis
    if total_requests >= 20 and unique_endpoints <= 1:
        risk_score += 10
        reasons.append("High request volume concentrated on one endpoint")

    # Isolation Forest prediction
    if prediction == -1:
        risk_score += 15
        reasons.append("Isolation Forest identified anomalous behaviour")

    # Model anomaly score
    if model_score < -0.15:
        risk_score += 10
        reasons.append("Strong anomaly score detected")
    elif model_score < -0.05:
        risk_score += 5
        reasons.append("Potentially suspicious anomaly score")

    risk_score = min(risk_score, 100)

    # Severity classification
    if risk_score >= 80:
        severity = "Critical"
    elif risk_score >= 60:
        severity = "High"
    elif risk_score >= 30:
        severity = "Medium"
    else:
        severity = "Low"

    if not reasons:
        reasons.append("No significant suspicious behaviour detected")

    return {
        "risk_score": risk_score,
        "severity": severity,
        "reasons": reasons
    }


# ============================================================
# 2. LIVE ANOMALY DETECTION
# ============================================================

def run_anomaly_detection():

    db = SessionLocal()

    try:

        user_statistics = defaultdict(
            lambda: {
                "total_requests": 0,
                "denied_requests": 0,
                "rate_limited_requests": 0,
                "failed_logins": 0,
                "endpoints": set()
            }
        )

        # ----------------------------------------------------
        # Collect API analytics
        # ----------------------------------------------------

        analytics_records = db.query(APIAnalytics).all()

        for record in analytics_records:

            username = record.username

            if not username:
                continue

            stats = user_statistics[username]

            stats["total_requests"] += 1

            if record.endpoint:
                stats["endpoints"].add(record.endpoint)

            # APIAnalytics stores a descriptive status string
            # (for example: Allowed, Denied, Rate Limited),
            # not an HTTP status_code attribute.
            record_status = (record.status or "").strip().lower()

            if record_status == "denied":
                stats["denied_requests"] += 1

            if record_status == "rate limited":
                stats["rate_limited_requests"] += 1

        # ----------------------------------------------------
        # Collect failed login attempts
        # ----------------------------------------------------

        failed_login_records = (
            db.query(AuditLog)
            .filter(
                AuditLog.action == "User Login",
                AuditLog.status == "Failed"
            )
            .all()
        )

        for record in failed_login_records:

            username = record.username

            if username:
                user_statistics[username]["failed_logins"] += 1

        # ----------------------------------------------------
        # Minimum data requirement
        # ----------------------------------------------------

        if len(user_statistics) < 3:

            return {
                "success": False,
                "message": (
                    "At least 3 users with activity are required "
                    "for anomaly detection."
                )
            }

        # ----------------------------------------------------
        # Prepare machine learning dataset
        # ----------------------------------------------------

        usernames = list(user_statistics.keys())

        feature_data = []

        for username in usernames:

            stats = user_statistics[username]

            stats["unique_endpoints"] = len(stats["endpoints"])

            feature_data.append([
                stats["total_requests"],
                stats["denied_requests"],
                stats["failed_logins"],
                stats["rate_limited_requests"],
                stats["unique_endpoints"]
            ])

        X = np.array(feature_data)

        # ----------------------------------------------------
        # Feature scaling
        # ----------------------------------------------------

        scaler = StandardScaler()

        X_scaled = scaler.fit_transform(X)

        # ----------------------------------------------------
        # Isolation Forest model
        # ----------------------------------------------------

        model = IsolationForest(
            n_estimators=150,
            contamination="auto",
            max_samples="auto",
            random_state=42
        )

        predictions = model.fit_predict(X_scaled)

        anomaly_scores = model.decision_function(X_scaled)

        # ----------------------------------------------------
        # Process detection results
        # ----------------------------------------------------

        detection_results = []

        anomaly_count = 0
        normal_count = 0

        severity_statistics = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0
        }

        # Remove previous detection results
        db.query(AnomalyResult).delete()

        for index, username in enumerate(usernames):

            stats = user_statistics[username]

            prediction = int(predictions[index])
            model_score = float(anomaly_scores[index])

            # Calculate risk score
            risk_information = calculate_risk_score(
                stats,
                prediction,
                model_score
            )

            risk_score = risk_information["risk_score"]
            severity = risk_information["severity"]
            reasons = risk_information["reasons"]

            if prediction == -1:
                result = "Anomaly"
                anomaly_count += 1
            else:
                result = "Normal"
                normal_count += 1

            severity_statistics[severity] += 1

            # ------------------------------------------------
            # Save results to database
            # ------------------------------------------------

            anomaly_record = AnomalyResult(
                username=username,
                total_requests=stats["total_requests"],
                denied_requests=stats["denied_requests"],
                failed_logins=stats["failed_logins"],
                rate_limited_requests=stats["rate_limited_requests"],
                unique_endpoints=stats["unique_endpoints"],
                result=result,
                anomaly_score=str(round(model_score, 4))
            )

            db.add(anomaly_record)

            detection_results.append({
                "username": username,
                "total_requests": stats["total_requests"],
                "denied_requests": stats["denied_requests"],
                "failed_logins": stats["failed_logins"],
                "rate_limited_requests": stats["rate_limited_requests"],
                "unique_endpoints": stats["unique_endpoints"],
                "result": result,
                "anomaly_score": round(model_score, 4),
                "risk_score": risk_score,
                "severity": severity,
                "reasons": reasons
            })

        db.commit()

        # ----------------------------------------------------
        # Detection summary
        # ----------------------------------------------------

        total_users = len(usernames)

        anomaly_percentage = (
            (anomaly_count / total_users) * 100
            if total_users > 0 else 0
        )

        return {
            "success": True,
            "analysed_users": total_users,
            "anomaly_count": anomaly_count,
            "normal_count": normal_count,
            "anomaly_percentage": round(anomaly_percentage, 2),
            "severity_statistics": severity_statistics,
            "detection_results": detection_results,
            "algorithm": "Isolation Forest",
            "risk_scoring": "Rule-based Risk Assessment",
            "features_analysed": [
                "Total API Requests",
                "Denied Requests",
                "Failed Login Attempts",
                "Rate-Limited Requests",
                "Unique Endpoints"
            ]
        }

    except Exception as error:

        db.rollback()

        return {
            "success": False,
            "message": str(error)
        }

    finally:

        db.close()


# ============================================================
# 3. ML MODEL PERFORMANCE EVALUATION
# ============================================================

def evaluate_model_performance():

    """
    Evaluates Isolation Forest using a separate synthetic,
    labelled API activity dataset.

    Labels:
        0 = Normal activity
        1 = Suspicious activity

    This evaluation is for demonstration and testing.
    It does not represent verified real-world attack accuracy.
    """

    try:

        rng = np.random.default_rng(42)

        # ----------------------------------------------------
        # Generate normal training data
        # ----------------------------------------------------

        normal_training = np.column_stack([
            rng.integers(5, 80, 200),
            rng.integers(0, 4, 200),
            rng.integers(0, 2, 200),
            rng.integers(0, 3, 200),
            rng.integers(2, 12, 200)
        ])

        # ----------------------------------------------------
        # Generate normal test data
        # ----------------------------------------------------

        normal_test = np.column_stack([
            rng.integers(5, 80, 60),
            rng.integers(0, 4, 60),
            rng.integers(0, 2, 60),
            rng.integers(0, 3, 60),
            rng.integers(2, 12, 60)
        ])

        # ----------------------------------------------------
        # Generate suspicious test data
        # ----------------------------------------------------

        attack_test = np.column_stack([
            rng.integers(200, 800, 40),
            rng.integers(10, 60, 40),
            rng.integers(5, 30, 40),
            rng.integers(5, 40, 40),
            rng.integers(1, 4, 40)
        ])

        # ----------------------------------------------------
        # Combine test datasets
        # ----------------------------------------------------

        X_test = np.vstack([
            normal_test,
            attack_test
        ])

        y_test = np.array(
            [0] * len(normal_test) +
            [1] * len(attack_test)
        )

        # ----------------------------------------------------
        # Scale features
        # ----------------------------------------------------

        scaler = StandardScaler()

        X_train_scaled = scaler.fit_transform(
            normal_training
        )

        X_test_scaled = scaler.transform(
            X_test
        )

        # ----------------------------------------------------
        # Train Isolation Forest
        # ----------------------------------------------------

        model = IsolationForest(
            n_estimators=150,
            contamination=0.05,
            random_state=42
        )

        model.fit(X_train_scaled)

        # ----------------------------------------------------
        # Predict test samples
        # ----------------------------------------------------

        predictions = model.predict(X_test_scaled)

        # Isolation Forest:
        # -1 = Anomaly
        #  1 = Normal

        y_pred = np.where(
            predictions == -1,
            1,
            0
        )

        anomaly_scores = -model.decision_function(
            X_test_scaled
        )

        # ----------------------------------------------------
        # Calculate evaluation metrics
        # ----------------------------------------------------

        accuracy = accuracy_score(
            y_test,
            y_pred
        )

        precision = precision_score(
            y_test,
            y_pred,
            zero_division=0
        )

        recall = recall_score(
            y_test,
            y_pred,
            zero_division=0
        )

        f1 = f1_score(
            y_test,
            y_pred,
            zero_division=0
        )

        # ----------------------------------------------------
        # Confusion Matrix
        # ----------------------------------------------------

        matrix = confusion_matrix(
            y_test,
            y_pred,
            labels=[0, 1]
        )

        tn, fp, fn, tp = matrix.ravel()

        # ----------------------------------------------------
        # False Positive Rate
        # ----------------------------------------------------

        false_positive_rate = (
            fp / (fp + tn)
            if (fp + tn) > 0 else 0
        )

        # ----------------------------------------------------
        # ROC Curve and AUC
        # ----------------------------------------------------

        fpr, tpr, roc_thresholds = roc_curve(
            y_test,
            anomaly_scores
        )

        roc_auc = roc_auc_score(
            y_test,
            anomaly_scores
        )

        # ----------------------------------------------------
        # Precision-Recall Curve
        # ----------------------------------------------------

        pr_precision, pr_recall, pr_thresholds = (
            precision_recall_curve(
                y_test,
                anomaly_scores
            )
        )

        # ----------------------------------------------------
        # Return evaluation results
        # ----------------------------------------------------

        return {

            "success": True,

            "evaluation_type": (
                "Synthetic labelled test dataset"
            ),

            "algorithm": "Isolation Forest",

            "total_test_samples": len(y_test),

            "normal_samples": int(
                np.sum(y_test == 0)
            ),

            "attack_samples": int(
                np.sum(y_test == 1)
            ),

            "accuracy": round(
                accuracy * 100, 2
            ),

            "precision": round(
                precision * 100, 2
            ),

            "recall": round(
                recall * 100, 2
            ),

            "f1_score": round(
                f1 * 100, 2
            ),

            "false_positive_rate": round(
                false_positive_rate * 100, 2
            ),

            "roc_auc": round(
                roc_auc * 100, 2
            ),

            "confusion_matrix": {

                "true_negative": int(tn),

                "false_positive": int(fp),

                "false_negative": int(fn),

                "true_positive": int(tp)

            },

            "roc_curve": {

                "fpr": fpr.tolist(),

                "tpr": tpr.tolist()

            },

            "precision_recall_curve": {

                "precision": pr_precision.tolist(),

                "recall": pr_recall.tolist()

            }

        }

    except Exception as error:

        return {
            "success": False,
            "message": str(error)
        }