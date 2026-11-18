import math

class PureLogisticModel:
    def __init__(self, weights, bias, feature_names):
        self.weights = weights
        self.bias = bias
        self.feature_names = feature_names

    def _sigmoid(self, z):
        if z < -20:
            return 0.0
        if z > 20:
            return 1.0
        return 1.0 / (1.0 + math.exp(-z))

    def predict_proba(self, X):
        results = []
        for row in X:
            if isinstance(row, dict):
                vals = [row.get(name, 0.0) for name in self.feature_names]
            else:
                vals = row
            z = self.bias + sum(w * v for w, v in zip(self.weights, vals))
            prob = self._sigmoid(z)
            results.append([1.0 - prob, prob])
        return results

    def predict(self, X, threshold=0.5):
        probs = self.predict_proba(X)
        return [1 if p[1] >= threshold else 0 for p in probs]
