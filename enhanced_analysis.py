from ecdsa import SigningKey, SECP256k1, util
import hashlib
import random
from typing import Tuple, List, Dict, Any
import hmac
import numpy as np
from scipy import stats, linalg
import sympy as sp
from collections import defaultdict
import rich
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box
from rich.text import Text
import matplotlib.pyplot as plt
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler
import warnings
import concurrent.futures
from dataclasses import dataclass
from enum import Enum

class VulnerabilityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class SignatureMetadata:
    timestamp: float
    computation_time: float
    bit_length: int
    entropy: float

class ECDSAAdvancedAnalyzer:
    def __init__(self):
        self.curve = SECP256k1
        self.order = SECP256k1.order
        self.console = Console()
        self.vulnerabilities_found = defaultdict(list)

    def generate_keypair(self) -> Tuple[SigningKey, bytes]:
        """Generate a new ECDSA keypair"""
        private_key = SigningKey.generate(curve=self.curve)
        public_key = private_key.get_verifying_key().to_string()
        return private_key, public_key

    def complete_signature_analysis(self, signatures: List[Tuple[bytes, int, int]], 
                                  metadata: List[SignatureMetadata] = None) -> Dict[str, Any]:
        """Comprehensive signature analysis"""
        analysis = {
            "basic_vulnerabilities": self._analyze_basic_vulnerabilities(signatures),
            "polynomial_analysis": self._polynomial_analysis(signatures),
            "lattice_vulnerability": self._analyze_lattice_vulnerability(signatures),
            "timing_patterns": self._analyze_timing_patterns(signatures),
            "nonce_bias": self._analyze_nonce_bias(signatures),
            "batch_vulnerability": self._analyze_batch_signatures(signatures),
            "differential_analysis": self._differential_power_analysis_simulation(signatures),
            "hidden_number_problem": self._analyze_hnp_vulnerability(signatures),
            "side_channel_leakage": self._analyze_side_channel_leakage(signatures, metadata),
            "bleichenbacher_attack": self._analyze_bleichenbacher_vulnerability(signatures),
            "prefix_lattice_attack": self._analyze_prefix_lattice(signatures),
            "fault_injection": self._simulate_fault_injection(signatures),
            "quantum_vulnerability": self._assess_quantum_vulnerability(signatures),
            "zero_value_attack": self._analyze_zero_value_vulnerability(signatures),
            "timing_correlation": self._analyze_timing_correlation(signatures, metadata),
            "entropy_analysis": self._analyze_entropy_patterns(signatures),
            "modular_arithmetic": self._analyze_modular_patterns(signatures),
            "recommendations": []
        }
        
        analysis.update(self._ml_based_analysis(signatures))
        self._generate_advanced_recommendations(analysis)
        return analysis

    def _analyze_basic_vulnerabilities(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Basic vulnerability analysis"""
        result = {
            "reused_nonce": False,
            "weak_randomness": False,
            "patterns_found": [],
            "affected_signatures": []
        }
        
        r_values = [sig[1] for sig in signatures]
        s_values = [sig[2] for sig in signatures]
        
        # Check for reused nonces
        if len(set(r_values)) < len(r_values):
            result["reused_nonce"] = True
            result["patterns_found"].append("Reused nonce detected")
            
        # Check for weak randomness patterns
        for i in range(len(signatures)-1):
            if abs(r_values[i] - r_values[i+1]) < 1000:
                result["weak_randomness"] = True
                result["patterns_found"].append(f"Sequential weakness in signatures {i}, {i+1}")
                result["affected_signatures"].extend([i, i+1])
                
        return result

    def _polynomial_analysis(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Detect polynomial patterns in k values"""
        result = {
            "polynomial_pattern_detected": False,
            "degree_estimate": None,
            "confidence": 0.0,
            "details": []
        }

        r_values = [sig[1] for sig in signatures]
        s_values = [sig[2] for sig in signatures]

        # Check for polynomial relationships between consecutive k values
        if len(r_values) >= 3:
            differences = [r_values[i+1] - r_values[i] for i in range(len(r_values)-1)]
            second_differences = [differences[i+1] - differences[i] for i in range(len(differences)-1)]
            
            # Check for linear patterns
            if all(abs(d - differences[0]) < 1000 for d in differences):
                result["polynomial_pattern_detected"] = True
                result["degree_estimate"] = 1
                result["confidence"] = 0.9
                result["details"].append("Linear pattern detected in k values")

            # Check for quadratic patterns
            elif all(abs(d - second_differences[0]) < 1000 for d in second_differences):
                result["polynomial_pattern_detected"] = True
                result["degree_estimate"] = 2
                result["confidence"] = 0.85
                result["details"].append("Quadratic pattern detected in k values")

        return result

    def _analyze_lattice_vulnerability(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze signatures for lattice-based attacks with improved numerical stability"""
        result = {
            "vulnerable_to_lattice": False,
            "basis_quality": None,
            "estimated_bits_leaked": 0,
            "details": []
        }

        if len(signatures) < 3:
            return result

        try:
            r_values = [sig[1] for sig in signatures]
            s_values = [sig[2] for sig in signatures]
            
            # Use log-space calculations to avoid overflow
            n = len(signatures)
            log_order = np.log2(float(self.order))
            
            # Create scaled basis to avoid overflow
            basis = np.zeros((n, n), dtype=np.float64)
            for i in range(n):
                # Use log-space for diagonal elements
                basis[i][i] = log_order - 30  # Scale down to avoid overflow
                r_scaled = float(r_values[i]) / float(self.order)
                basis[i][0] = np.log2(r_scaled) if r_scaled > 0 else -308  # Minimum double value
            
            # Use SVD for stability
            try:
                U, S, Vh = np.linalg.svd(basis, full_matrices=False)
                
                # Analyze singular values in log space
                log_condition = np.log2(S[0]) - np.log2(S[-1]) if S[-1] > 0 else 308
                
                if log_condition > 30:  # Threshold in log space
                    result["vulnerable_to_lattice"] = True
                    result["basis_quality"] = "Poor"
                    result["estimated_bits_leaked"] = int(log_condition)
                    result["details"].append({
                        "type": "SVD Analysis",
                        "log_condition_number": float(log_condition),
                        "significance": "High" if log_condition > 40 else "Medium"
                    })
            except Exception:
                # Fallback to simpler analysis if SVD fails
                diag_product = np.sum([row[i] for i, row in enumerate(basis)])
                if diag_product < -100:  # Threshold in log space
                    result["vulnerable_to_lattice"] = True
                    result["basis_quality"] = "Potentially Poor"
                    result["estimated_bits_leaked"] = int(abs(diag_product))
                    result["details"].append({
                        "type": "Fallback Analysis",
                        "diagonal_sum": float(diag_product),
                        "significance": "Medium"
                    })
            
            # Additional checks in safer numeric range
            if result["vulnerable_to_lattice"]:
                # Analyze scaled values for patterns
                scaled_rs = [float(r % self.order) / float(self.order) for r in r_values]
                scaled_diffs = np.diff(scaled_rs)
                if np.any(np.abs(scaled_diffs) < 1e-6):
                    result["details"].append({
                        "type": "Close Values",
                        "description": "Detected very close signature values",
                        "significance": "High"
                    })

        except Exception as e:
            result["details"].append({
                "type": "Error",
                "description": f"Analysis error: {str(e)}",
                "significance": "Unknown"
            })

        return result

    def _lll_reduce(self, basis: List[List[float]], delta: float = 0.75) -> List[List[float]]:
        """Numerically stable LLL lattice basis reduction"""
        try:
            basis = np.array(basis, dtype=np.float64)
            n = len(basis)
            
            # Pre-condition the basis
            scales = np.linalg.norm(basis, axis=1)
            scales[scales == 0] = 1
            basis = basis / scales[:, np.newaxis]
            
            def gram_schmidt_stable():
                Q = basis.copy()
                for i in range(n):
                    for j in range(i):
                        # Stable dot product
                        num = np.sum((Q[i] * Q[j]))
                        denom = np.sum((Q[j] * Q[j]))
                        if abs(denom) > 1e-15:  # Numerical stability threshold
                            Q[i] = Q[i] - (num/denom) * Q[j]
                return Q

            k = 1
            max_iterations = n * 10  # Prevent infinite loops
            iterations = 0
            
            while k < n and iterations < max_iterations:
                try:
                    Q = gram_schmidt_stable()
                    
                    # Size reduction with stability checks
                    for j in range(k-1, -1, -1):
                        q_norm = np.sum((Q[j] * Q[j]))
                        if q_norm > 1e-15:
                            mu = round(np.sum((basis[k] * Q[j])) / q_norm)
                            if abs(mu) > 0:
                                basis[k] = basis[k] - mu * basis[j]
                    
                    # LLL condition check with numerical stability
                    left = np.sum((Q[k] * Q[k]))
                    right = (delta - 1e-10) * np.sum((Q[k-1] * Q[k-1]))
                    
                    if left >= right:
                        k += 1
                    else:
                        basis[k], basis[k-1] = basis[k-1].copy(), basis[k].copy()
                        k = max(k-1, 1)
                    
                    iterations += 1
                except Exception:
                    k += 1
                    iterations += 1
            
            # Restore scaling
            basis = basis * scales[:, np.newaxis]
            
        except Exception as e:
            # Return original basis if reduction fails
            return basis
            
        return basis.tolist()


    def _analyze_timing_patterns(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Basic timing pattern analysis"""
        result = {
            "timing_vulnerability_detected": False,
            "patterns": [],
            "risk_level": "Low",
            "timing_analysis": {
                "statistical_significance": 0.0,
                "pattern_consistency": 0.0,
                "detected_anomalies": []
            }
        }

        r_values = [sig[1] for sig in signatures]
        hamming_weights = [bin(r).count('1') for r in r_values]
        
        mean_hw = np.mean(hamming_weights)
        std_hw = np.std(hamming_weights)
        
        if std_hw < 5:
            result["timing_vulnerability_detected"] = True
            result["risk_level"] = "High"
            result["patterns"].append({
                "type": "Consistent Hamming weight",
                "mean": mean_hw,
                "std_dev": std_hw,
                "significance": "High"
            })
            
        result["timing_analysis"]["statistical_significance"] = 1.0 - (std_hw / mean_hw)
        result["timing_analysis"]["pattern_consistency"] = len(result["patterns"]) / len(signatures)
            
        return result
    def _analyze_modular_patterns(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze patterns in modular arithmetic operations"""
        result = {
            "modular_weakness": False,
            "patterns_detected": [],
            "vulnerability_type": None,
            "exploitation_difficulty": "High",
            "exploitation_result": {
                "type": "None",
                "severity": "Low",
                "complexity": "High",
                "details": []
            }
        }
        
        try:
            r_values = [sig[1] for sig in signatures]
            s_values = [sig[2] for sig in signatures]
            
            # Check for patterns in modular operations
            for i in range(len(signatures) - 1):
                r_diff = (r_values[i+1] - r_values[i]) % self.order
                s_diff = (s_values[i+1] - s_values[i]) % self.order
                
                if r_diff * s_diff % self.order < 1000:
                    result["modular_weakness"] = True
                    result["patterns_detected"].append(f"Low modular product in signatures {i}, {i+1}")
                    result["vulnerability_type"] = "Modular multiplication weakness"
                    result["exploitation_result"] = {
                        "type": "Modular arithmetic weakness",
                        "affected_pairs": f"Signatures {i} and {i+1}",
                        "modular_differences": {
                            "r_diff": r_diff,
                            "s_diff": s_diff,
                            "product": r_diff * s_diff % self.order
                        },
                        "risk_assessment": {
                            "severity": "High" if r_diff * s_diff % self.order < 100 else "Medium",
                            "exploitability": "Feasible",
                            "complexity": "Moderate",
                            "prerequisites": "Access to consecutive signatures"
                        },
                        "potential_attacks": [
                            "Partial key recovery",
                            "Signature forgery",
                            "Nonce bias exploitation"
                        ],
                        "estimated_complexity": {
                            "time": "Hours to days",
                            "memory": "Moderate",
                            "success_rate": f"{min(90, int(1000 / (r_diff * s_diff % self.order + 1)))}%"
                        }
                    }
                    result["exploitation_difficulty"] = "Medium"
                    
            # Additional modular pattern checks
            for i in range(len(signatures)):
                # Check for weak modular residues
                if r_values[i] % 2 == 0 or s_values[i] % 2 == 0:
                    result["modular_weakness"] = True
                    result["patterns_detected"].append(f"Even modular values in signature {i}")
                    
                # Check for small modular values
                if r_values[i] < 1000 or s_values[i] < 1000:
                    result["modular_weakness"] = True
                    result["patterns_detected"].append(f"Small modular values in signature {i}")
                    
                # Check for values close to order
                if (self.order - r_values[i]) < 1000 or (self.order - s_values[i]) < 1000:
                    result["modular_weakness"] = True
                    result["patterns_detected"].append(f"Near-order values in signature {i}")
            
            # If any weakness is found, update final assessment
            if result["modular_weakness"]:
                if len(result["patterns_detected"]) > 3:
                    result["exploitation_difficulty"] = "Low"
                    result["vulnerability_type"] = "Multiple modular weaknesses"
                    
            # Add statistical analysis
            result["statistical_analysis"] = self._analyze_modular_statistics(r_values, s_values)
            
        except Exception as e:
            result["error"] = str(e)
            
        return result

    def _analyze_modular_statistics(self, r_values: List[int], s_values: List[int]) -> Dict:
        """Analyze statistical properties of modular values"""
        stats = {
            "r_value_stats": {},
            "s_value_stats": {},
            "correlations": {},
            "anomalies": []
        }
        
        try:
            # Normalize values for statistical analysis
            norm_r = [float(r % self.order) / float(self.order) for r in r_values]
            norm_s = [float(s % self.order) / float(self.order) for s in s_values]
            
            # Basic statistics
            stats["r_value_stats"] = {
                "mean": float(np.mean(norm_r)),
                "std": float(np.std(norm_r)),
                "min": float(np.min(norm_r)),
                "max": float(np.max(norm_r))
            }
            
            stats["s_value_stats"] = {
                "mean": float(np.mean(norm_s)),
                "std": float(np.std(norm_s)),
                "min": float(np.min(norm_s)),
                "max": float(np.max(norm_s))
            }
            
            # Correlation analysis
            if len(norm_r) > 1 and len(norm_s) > 1:
                correlation = float(np.corrcoef(norm_r, norm_s)[0,1])
                stats["correlations"]["r_s_correlation"] = correlation
                
                if abs(correlation) > 0.7:
                    stats["anomalies"].append({
                        "type": "High R-S Correlation",
                        "value": correlation,
                        "severity": "High"
                    })
            
            # Check for clustering
            for values, name in [(norm_r, 'r'), (norm_s, 's')]:
                if len(values) >= 4:
                    q1, q3 = np.percentile(values, [25, 75])
                    iqr = q3 - q1
                    outliers = [v for v in values if v < q1 - 1.5*iqr or v > q3 + 1.5*iqr]
                    if outliers:
                        stats["anomalies"].append({
                            "type": f"{name.upper()} Value Outliers",
                            "count": len(outliers),
                            "severity": "Medium"
                        })
                        
        except Exception as e:
            stats["error"] = str(e)
            
        return stats

    def _analyze_nonce_bias(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Detect biases in nonce generation"""
        result = {
            "bias_detected": False,
            "bias_patterns": [],
            "statistical_significance": 0.0,
            "nonce_analysis": {
                "bit_distribution": {},
                "value_distribution": {},
                "correlation_score": 0.0
            }
        }

        r_values = [sig[1] for sig in signatures]
        
        # Analyze bit patterns
        bits = [format(r, '0256b') for r in r_values]
        bit_counts = defaultdict(int)
        
        # Count bit patterns
        for bit_str in bits:
            for i in range(len(bit_str) - 7):
                pattern = bit_str[i:i+8]
                bit_counts[pattern] += 1
        
        expected_count = len(signatures) / 256
        
        for pattern, count in bit_counts.items():
            if count > 2 * expected_count:
                result["bias_detected"] = True
                result["bias_patterns"].append({
                    "pattern": pattern,
                    "count": count,
                    "expected_count": expected_count,
                    "deviation": count / expected_count
                })
                result["statistical_significance"] = max(
                    result["statistical_significance"],
                    count / expected_count
                )

        # Calculate bit distribution
        all_bits = ''.join(bits)
        result["nonce_analysis"]["bit_distribution"] = {
            "zeros": all_bits.count('0') / len(all_bits),
            "ones": all_bits.count('1') / len(all_bits)
        }

        # Analyze value distribution safely
        try:
            normalized_values = [float(r % self.order) / float(self.order) for r in r_values]
            hist, bin_edges = np.histogram(normalized_values, bins=10, range=(0, 1))
            result["nonce_analysis"]["value_distribution"] = {
                "histogram": hist.tolist(),
                "bin_edges": bin_edges.tolist()
            }
        except Exception as e:
            result["nonce_analysis"]["value_distribution"] = {
                "error": str(e),
                "histogram": [],
                "bin_edges": []
            }

        return result

    def _analyze_batch_signatures(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze vulnerability to batch signature attacks"""
        result = {
            "batch_vulnerability": False,
            "weak_combinations": [],
            "risk_assessment": "Low",
            "exploitation_potential": {
                "complexity": "High",
                "success_probability": 0.0,
                "required_resources": "Unknown"
            }
        }

        if len(signatures) < 2:
            return result

        r_values = [sig[1] for sig in signatures]
        s_values = [sig[2] for sig in signatures]

        # Check for dangerous linear combinations
        for i in range(len(signatures)-1):
            r1, s1 = r_values[i], s_values[i]
            r2, s2 = r_values[i+1], s_values[i+1]
            
            mod_relation = abs(r1 * s2 - r2 * s1) % self.order
            if mod_relation < 1000:
                result["batch_vulnerability"] = True
                result["weak_combinations"].append({
                    "signature_pair": (i, i+1),
                    "relation_value": mod_relation,
                    "risk_level": "High" if mod_relation < 100 else "Medium"
                })
                result["risk_assessment"] = "High"
                result["exploitation_potential"]["success_probability"] = 0.8
                result["exploitation_potential"]["complexity"] = "Medium"
                result["exploitation_potential"]["required_resources"] = "Standard computing resources"

        return result

    def _differential_power_analysis_simulation(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Simulate differential power analysis attacks"""
        result = {
            "dpa_vulnerable": False,
            "power_traces": [],
            "correlation_score": 0.0,
            "attack_feasibility": "Low",
            "vulnerability_details": []
        }

        for r, s in zip([sig[1] for sig in signatures], [sig[2] for sig in signatures]):
            # Simulate power consumption based on hamming weight
            hw_r = bin(r).count('1')
            hw_s = bin(s).count('1')
            
            # Generate synthetic power trace
            power_trace = []
            try:
                for i in range(256):
                    bit_r = (r >> i) & 1
                    bit_s = (s >> i) & 1
                    power = 0.8 if bit_r else 0.2
                    power += 0.6 if bit_s else 0.1
                    power += random.uniform(-0.1, 0.1)  # Add noise
                    power_trace.append(power)
                
                result["power_traces"].append(power_trace)
            except Exception as e:
                result["vulnerability_details"].append(f"Error in trace generation: {str(e)}")
                continue

        # Analyze power traces for patterns
        if len(result["power_traces"]) >= 2:
            try:
                traces = np.array(result["power_traces"])
                correlation = np.corrcoef(traces)
                
                # Look for high correlations
                peak_correlations = np.max(np.abs(correlation - np.eye(correlation.shape[0])), axis=0)
                if np.any(peak_correlations > 0.7):
                    result["dpa_vulnerable"] = True
                    result["correlation_score"] = float(np.max(peak_correlations))
                    result["attack_feasibility"] = "High"
                    result["vulnerability_details"].append(
                        f"High correlation detected: {result['correlation_score']:.3f}"
                    )
                
            except Exception as e:
                result["vulnerability_details"].append(f"Error in correlation analysis: {str(e)}")

        return result

    def _analyze_hnp_vulnerability(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze Hidden Number Problem vulnerability"""
        result = {
            "vulnerable_to_hnp": False,
            "bits_leaked": 0,
            "confidence": 0.0,
            "attack_complexity": "N/A",
            "attack_feasibility": {
                "possible": False,
                "required_samples": 0,
                "estimated_time": "N/A",
                "success_probability": 0.0
            }
        }
        
        try:
            r_values = [sig[1] for sig in signatures]
            s_values = [sig[2] for sig in signatures]
            
            if len(signatures) >= 4:
                # Construct lattice for HNP analysis
                lattice = np.zeros((len(signatures) + 1, len(signatures) + 1))
                for i in range(len(signatures)):
                    lattice[i][i] = self.order
                    lattice[i][-1] = r_values[i]
                lattice[-1][-1] = 1
                
                determinant = abs(np.linalg.det(lattice))
                if determinant < self.order ** (len(signatures) / 2):
                    result["vulnerable_to_hnp"] = True
                    result["bits_leaked"] = int(np.log2(self.order / determinant))
                    result["confidence"] = min(1.0, result["bits_leaked"] / 256)
                    result["attack_complexity"] = f"2^{int(np.log2(determinant))}"
                    
                    result["attack_feasibility"] = {
                        "possible": True,
                        "required_samples": len(signatures),
                        "estimated_time": self._estimate_hnp_time(result["bits_leaked"]),
                        "success_probability": min(1.0, result["bits_leaked"] / 128)
                    }

        except Exception as e:
            result["error"] = str(e)
            
        return result

    def _analyze_side_channel_leakage(self, signatures: List[Tuple[bytes, int, int]], 
                                    metadata: List[SignatureMetadata]) -> Dict:
        """Advanced side-channel leakage analysis"""
        result = {
            "timing_leakage": False,
            "power_leakage": False,
            "cache_vulnerability": False,
            "leakage_points": [],
            "vulnerability_score": 0.0
        }
        
        if metadata:
            computation_times = [m.computation_time for m in metadata]
            mean_time = np.mean(computation_times)
            std_time = np.std(computation_times)
            
            # Check for timing correlations with bit patterns
            for i, sig in enumerate(signatures):
                r_bits = format(sig[1], '0256b')
                hamming_weight = r_bits.count('1')
                if abs(computation_times[i] - mean_time) > 2 * std_time:
                    if hamming_weight > 128:
                        result["timing_leakage"] = True
                        result["leakage_points"].append({
                            "type": "timing",
                            "signature_index": i,
                            "hamming_weight": hamming_weight,
                            "deviation": abs(computation_times[i] - mean_time) / std_time
                        })

            # Analyze cache timing patterns
            time_differences = np.diff(computation_times)
            if np.any(time_differences > 3 * std_time):
                result["cache_vulnerability"] = True
                result["leakage_points"].append({
                    "type": "cache_timing",
                    "anomalous_differences": time_differences[time_differences > 3 * std_time].tolist()
                })

            # Calculate overall vulnerability score
            result["vulnerability_score"] = (
                (result["timing_leakage"] * 0.4) + 
                (result["power_leakage"] * 0.3) + 
                (result["cache_vulnerability"] * 0.3)
            )
            
        return result

    def _analyze_bleichenbacher_vulnerability(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze vulnerability to Bleichenbacher's attack"""
        result = {
            "vulnerable": False,
            "biased_bits": [],
            "estimated_complexity": float('inf'),
            "attack_feasibility": "Not Feasible",
            "details": []
        }

        try:
            r_values = [sig[1] for sig in signatures]
            
            # Check for biased bits in signatures
            for bit_pos in range(256):
                bit_count = sum(1 for r in r_values if (r >> bit_pos) & 1)
                bias = abs(bit_count/len(r_values) - 0.5)
                
                if bias > 0.1:  # Significant bias threshold
                    result["vulnerable"] = True
                    result["biased_bits"].append({
                        "position": bit_pos,
                        "bias": float(bias),
                        "count": bit_count
                    })

            # Calculate attack complexity
            if result["vulnerable"]:
                unbiased_bits = 256 - len(result["biased_bits"])
                result["estimated_complexity"] = 2 ** unbiased_bits
                
                if result["estimated_complexity"] < 2**80:
                    result["attack_feasibility"] = "Practically Feasible"
                elif result["estimated_complexity"] < 2**128:
                    result["attack_feasibility"] = "Theoretically Feasible"
                
        except Exception as e:
            result["details"].append(f"Analysis error: {str(e)}")

        return result

    def _analyze_prefix_lattice(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze vulnerability to prefix-based lattice attacks"""
        result = {
            "vulnerable_to_prefix": False,
            "common_prefixes": [],
            "prefix_length": 0,
            "attack_complexity": float('inf'),
            "attack_details": {
                "feasibility": "Not Feasible",
                "required_samples": 0,
                "best_prefix_length": 0,
                "time_estimate": "N/A"
            }
        }
        
        try:
            r_strings = [format(sig[1], '0256b') for sig in signatures]
            s_strings = [format(sig[2], '0256b') for sig in signatures]
            
            # Analyze different prefix lengths
            for length in range(8, 65, 8):
                r_prefixes = [s[:length] for s in r_strings]
                s_prefixes = [s[:length] for s in s_strings]
                
                r_prefix_counts = defaultdict(int)
                s_prefix_counts = defaultdict(int)
                
                for prefix in r_prefixes:
                    r_prefix_counts[prefix] += 1
                for prefix in s_prefixes:
                    s_prefix_counts[prefix] += 1
                
                r_max_freq = max(r_prefix_counts.values()) / len(signatures)
                s_max_freq = max(s_prefix_counts.values()) / len(signatures)
                
                if r_max_freq > 0.1 or s_max_freq > 0.1:
                    result["vulnerable_to_prefix"] = True
                    result["prefix_length"] = max(result["prefix_length"], length)
                    result["common_prefixes"].extend(
                        [k for k, v in r_prefix_counts.items() if v/len(signatures) > 0.1]
                    )
                    bits_exposed = int(length * (1 - min(r_max_freq, s_max_freq)))
                    result["attack_complexity"] = min(
                        result["attack_complexity"], 
                        2 ** (256 - bits_exposed)
                    )
            
            if result["vulnerable_to_prefix"]:
                result["attack_details"].update(
                    self._calculate_prefix_attack_details(
                        result["prefix_length"], 
                        result["attack_complexity"]
                    )
                )
                
        except Exception as e:
            result["error"] = str(e)
            
        return result

    def _simulate_fault_injection(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Simulate and analyze fault injection vulnerabilities"""
        result = {
            "fault_vulnerable": False,
            "vulnerable_operations": [],
            "fault_patterns": [],
            "risk_assessment": "Low",
            "simulation_results": {
                "bit_flips": [],
                "zero_bytes": [],
                "instruction_skips": [],
                "glitch_effects": []
            }
        }

        try:
            fault_types = ['bit_flip', 'zero_byte', 'instruction_skip', 'glitch']
            
            for fault in fault_types:
                if fault == 'bit_flip':
                    for i, (_, r, s) in enumerate(signatures):
                        for bit_pos in [0, 127, 255]:
                            flipped_r = r ^ (1 << bit_pos)
                            if self._verify_faulty_signature(flipped_r, s):
                                result["fault_vulnerable"] = True
                                result["simulation_results"]["bit_flips"].append({
                                    "signature_index": i,
                                    "bit_position": bit_pos,
                                    "severity": "High" if bit_pos in [0, 255] else "Medium"
                                })
                
                elif fault == 'zero_byte':
                    for i, (_, r, s) in enumerate(signatures):
                        for byte_pos in [0, 15, 31]:
                            zero_byte_r = r & ~(0xFF << (byte_pos * 8))
                            if self._verify_faulty_signature(zero_byte_r, s):
                                result["fault_vulnerable"] = True
                                result["simulation_results"]["zero_bytes"].append({
                                    "signature_index": i,
                                    "byte_position": byte_pos,
                                    "severity": "High" if byte_pos in [0, 31] else "Medium"
                                })

            if result["fault_vulnerable"]:
                result["risk_assessment"] = self._assess_fault_injection_risk(result)
                
        except Exception as e:
            result["error"] = f"Fault simulation error: {str(e)}"

        return result

    def _verify_faulty_signature(self, r: int, s: int) -> bool:
        """Verify if a faulty signature could be exploitable"""
        if r == 0 or s == 0:
            return True
        if r >= self.order or s >= self.order:
            return True
        if r < 1000 or s < 1000:
            return True
        return False

    def _assess_fault_injection_risk(self, simulation_result: Dict) -> str:
        """Assess the overall risk level of fault injection vulnerabilities"""
        risk_score = 0
        
        bit_flip_success = len(simulation_result["simulation_results"]["bit_flips"])
        zero_byte_success = len(simulation_result["simulation_results"]["zero_bytes"])
        
        risk_score += bit_flip_success * 0.3
        risk_score += zero_byte_success * 0.4
        
        if risk_score > 2.0:
            return "Critical"
        elif risk_score > 1.0:
            return "High"
        elif risk_score > 0.5:
            return "Medium"
        return "Low"

    def _assess_quantum_vulnerability(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Assess vulnerability to quantum attacks"""
        result = {
            "quantum_vulnerable": True,
            "estimated_qubits": 2048,
            "breaking_time_estimate": "Hours to days on theoretical quantum computer",
            "quantum_safety_score": 0,
            "mitigation_possible": False,
            "detailed_analysis": {
                "shor_algorithm": self._analyze_shor_requirements([sig[1] for sig in signatures]),
                "grover_algorithm": self._analyze_grover_applicability([sig[2] for sig in signatures]),
                "quantum_resources": self._estimate_quantum_resources(),
                "timeline_estimate": self._estimate_quantum_timeline()
            }
        }
        
        result["quantum_safety_score"] = self._calculate_quantum_safety_score(result["detailed_analysis"])
        result["quantum_attack_vectors"] = self._identify_quantum_attack_vectors()
        result["recommendations"] = self._generate_quantum_recommendations(result["quantum_safety_score"])
            
        return result

    def _analyze_shor_requirements(self, r_values: List[int]) -> Dict:
        return {
            "logical_qubits": 2048,
            "physical_qubits": 2048 * 100,
            "circuit_depth": "O(n³)",
            "success_probability": 0.9,
            "vulnerabilities": [
                "Period finding susceptibility",
                "Superposition of all curve points",
                "Quantum Fourier transform applicability"
            ]
        }

    def _analyze_grover_applicability(self, s_values: List[int]) -> Dict:
        return {
            "speedup_factor": "Quadratic",
            "applicable_attacks": [
                "Quantum collision finding",
                "Superposition signature forgery"
            ],
            "required_qubits": 512,
            # Fix for sqrt calculation
            "estimated_iterations": int(float(np.sqrt(float(2**128)))),  # Using 2**128 to avoid overflow
            "success_probability": 0.9
        }

    def _estimate_quantum_resources(self) -> Dict:
        return {
            "minimum_qubits": 2048,
            "error_correction_overhead": 100,
            "total_physical_qubits": 2048 * 100,
            "coherence_time_needed": "Hours",
            "gate_fidelity_required": 0.9999
        }

    def _estimate_quantum_timeline(self) -> Dict:
        return {
            "earliest_threat": "5-10 years",
            "realistic_estimate": "10-15 years",
            "confidence_level": "Medium",
            "dependent_factors": [
                "Quantum hardware development",
                "Error correction advancement",
                "Algorithm optimization"
            ]
        }

    def _calculate_quantum_safety_score(self, analysis: Dict) -> int:
        """Calculate quantum safety score (0-100)"""
        score = 100  # Start with perfect score

        # Factor in Shor's algorithm vulnerability
        if analysis["shor_algorithm"]["success_probability"] > 0.8:
            score -= 40
            
        # Consider Grover's algorithm impact
        if analysis["grover_algorithm"]["success_probability"] > 0.8:
            score -= 30
            
        # Account for quantum resource requirements
        qubits_needed = analysis["quantum_resources"]["minimum_qubits"]
        if qubits_needed < 1000:
            score -= 30
        elif qubits_needed < 2000:
            score -= 20
        elif qubits_needed < 3000:
            score -= 10

        # Consider timeline estimates
        timeline = analysis["timeline_estimate"]
        if timeline["earliest_threat"] == "5-10 years":
            score -= 10
        elif timeline["earliest_threat"] == "1-5 years":
            score -= 20

        # Consider confidence level
        if timeline["confidence_level"] == "High":
            score -= 10
        elif timeline["confidence_level"] == "Medium":
            score -= 5

        return max(0, score)  # Ensure score doesn't go below 0

    def _identify_quantum_attack_vectors(self) -> List[Dict]:
        """Identify potential quantum attack vectors"""
        return [
            {
                "type": "Shor's Algorithm Attack",
                "description": "Exponential speedup in solving ECDLP",
                "impact": "Critical",
                "timeline": "Medium-term threat",
                "requirements": "Large-scale quantum computer"
            },
            {
                "type": "Grover's Algorithm Attack",
                "description": "Quadratic speedup in brute force attacks",
                "impact": "High",
                "timeline": "Long-term threat",
                "requirements": "Medium-scale quantum computer"
            },
            {
                "type": "Quantum Collision Attack",
                "description": "Faster collision finding in hash functions",
                "impact": "Medium",
                "timeline": "Medium-term threat",
                "requirements": "Specialized quantum circuits"
            }
        ]

    def _generate_quantum_recommendations(self, safety_score: int) -> List[Dict]:
        """Generate quantum-specific security recommendations"""
        recommendations = []
        
        if safety_score < 30:
            recommendations.append({
                "priority": "Critical",
                "title": "Immediate Quantum-Safe Migration Required",
                "description": "System is highly vulnerable to quantum attacks",
                "actions": [
                    "Migrate to quantum-resistant algorithms",
                    "Implement hybrid classical-quantum schemes",
                    "Prepare quantum-safe key management"
                ]
            })
        elif safety_score < 60:
            recommendations.append({
                "priority": "High",
                "title": "Quantum-Safe Migration Planning",
                "description": "Begin planning migration to quantum-safe algorithms",
                "actions": [
                    "Assess quantum-safe algorithm options",
                    "Develop migration strategy",
                    "Test quantum-safe implementations"
                ]
            })
        else:
            recommendations.append({
                "priority": "Medium",
                "title": "Quantum Risk Monitoring",
                "description": "Monitor quantum computing developments",
                "actions": [
                    "Track quantum computing progress",
                    "Evaluate emerging quantum-safe standards",
                    "Prepare preliminary migration plans"
                ]
            })
            
        return recommendations

    def _analyze_zero_value_vulnerability(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze vulnerability to zero-value attacks"""
        result = {
            "zero_value_vulnerable": False,
            "weak_value_patterns": [],
            "risk_level": "Low",
            "potential_exploits": []
        }

        try:
            r_values = [sig[1] for sig in signatures]
            s_values = [sig[2] for sig in signatures]

            for i, (r, s) in enumerate(zip(r_values, s_values)):
                if r < 1000 or s < 1000:
                    result["zero_value_vulnerable"] = True
                    result["weak_value_patterns"].append({
                        "type": "near_zero",
                        "signature_index": i,
                        "r_value": r if r < 1000 else None,
                        "s_value": s if s < 1000 else None
                    })
                    result["risk_level"] = "Critical"

                if abs(r - self.order) < 1000 or abs(s - self.order) < 1000:
                    result["zero_value_vulnerable"] = True
                    result["weak_value_patterns"].append({
                        "type": "near_order",
                        "signature_index": i,
                        "r_distance": abs(r - self.order) if abs(r - self.order) < 1000 else None,
                        "s_distance": abs(s - self.order) if abs(s - self.order) < 1000 else None
                    })
                    result["risk_level"] = max(result["risk_level"], "High")

                if self._is_weak_value(r) or self._is_weak_value(s):
                    result["weak_value_patterns"].append({
                        "type": "weak_structure",
                        "signature_index": i,
                        "pattern": self._identify_weak_pattern(r, s)
                    })

        except Exception as e:
            result["error"] = str(e)

        return result

    def _is_weak_value(self, value: int) -> bool:
        binary = bin(value)[2:]
        return binary.count('1') < 5 or len(set(binary)) < 3

    def _identify_weak_pattern(self, r: int, s: int) -> str:
        patterns = []
        
        if r < 1000 or s < 1000:
            patterns.append("small_value")
            
        r_bin = bin(r)[2:]
        s_bin = bin(s)[2:]
        
        if r_bin.count('1') < 5 or s_bin.count('1') < 5:
            patterns.append("low_hamming")
        if len(set(r_bin)) < 3 or len(set(s_bin)) < 3:
            patterns.append("low_entropy")
            
        return "_".join(patterns) if patterns else "none"

    def _analyze_timing_correlation(self, signatures: List[Tuple[bytes, int, int]], 
                                  metadata: List[SignatureMetadata]) -> Dict:
        """Analyze timing correlations in signature generation"""
        result = {
            "timing_correlations": False,
            "correlation_patterns": [],
            "statistical_confidence": 0.0,
            "exploitable_timing": False
        }

        if not metadata:
            return result

        try:
            times = np.array([m.computation_time for m in metadata])
            r_values = np.array([float(sig[1] % self.order) / float(self.order) for sig in signatures])
            
            correlation = np.corrcoef(times, r_values)[0,1]
            
            if abs(correlation) > 0.6:
                result["timing_correlations"] = True
                result["correlation_patterns"].append({
                    "type": "value_timing_correlation",
                    "correlation": float(correlation),
                    "significance": "High" if abs(correlation) > 0.8 else "Medium"
                })
                result["statistical_confidence"] = abs(correlation)
                result["exploitable_timing"] = abs(correlation) > 0.8

        except Exception as e:
            result["error"] = str(e)

        return result


    def _analyze_entropy_patterns(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Analyze entropy patterns in signatures"""
        result = {
            "entropy_weakness": False,
            "entropy_score": 0.0,
            "weak_patterns": [],
            "randomness_quality": "High"
        }

        try:
            r_values = [sig[1] for sig in signatures]
            s_values = [sig[2] for sig in signatures]
            
            r_entropy = self._calculate_entropy([format(r, '0256b') for r in r_values])
            s_entropy = self._calculate_entropy([format(s, '0256b') for s in s_values])
            
            result["entropy_score"] = (r_entropy + s_entropy) / 2
            
            if result["entropy_score"] < 0.9:
                result["entropy_weakness"] = True
                result["randomness_quality"] = "Low"
                result["weak_patterns"] = self._find_entropy_patterns(r_values)
                
        except Exception as e:
            result["error"] = str(e)

        return result

    def _calculate_entropy(self, bit_strings: List[str]) -> float:
        if not bit_strings:
            return 0.0
            
        all_bits = ''.join(bit_strings)
        length = len(all_bits)
        
        if length == 0:
            return 0.0
            
        probabilities = [all_bits.count(c) / length for c in set(all_bits)]
        return -sum(p * np.log2(p) for p in probabilities if p > 0)

    def _find_entropy_patterns(self, values: List[int]) -> List[Dict]:
        patterns = []
        for i, value in enumerate(values):
            binary = format(value, '0256b')
            if len(set(binary)) < 5:
                patterns.append({
                    "type": "low_unique_bits",
                    "position": i,
                    "unique_bits": len(set(binary))
                })
            
            repeating = self._find_repeating_sequences(binary)
            if repeating:
                patterns.append({
                    "type": "repeating_sequence",
                    "position": i,
                    "sequences": repeating
                })
                
        return patterns

    def _find_repeating_sequences(self, binary: str) -> List[str]:
        sequences = []
        for length in range(4, 9):
            for i in range(len(binary) - length):
                pattern = binary[i:i+length]
                if binary.count(pattern) > 2:
                    sequences.append({
                        "pattern": pattern,
                        "length": length,
                        "occurrences": binary.count(pattern)
                    })
        return sequences

    def _ml_based_analysis(self, signatures: List[Tuple[bytes, int, int]]) -> Dict:
        """Machine learning based pattern detection"""
        result = {
            "ml_anomalies": False,
            "detected_patterns": [],
            "cluster_analysis": {},
            "prediction_confidence": 0.0
        }
        
        try:
            features = np.array([[sig[1], sig[2]] for sig in signatures])
            scaled_features = StandardScaler().fit_transform(features)
            
            # Cluster analysis using DBSCAN
            clustering = DBSCAN(eps=0.3, min_samples=2).fit(scaled_features)
            labels = clustering.labels_
            
            n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
            result["cluster_analysis"] = {
                "num_clusters": n_clusters,
                "outliers": list(np.where(labels == -1)[0]),
                "cluster_sizes": [list(labels).count(i) for i in range(n_clusters)]
            }
            
            if n_clusters > 1:
                result["ml_anomalies"] = True
                result["prediction_confidence"] = 0.8
                
                for i in range(n_clusters):
                    cluster_points = features[labels == i]
                    pattern = self._analyze_cluster_patterns(cluster_points)
                    if pattern:
                        result["detected_patterns"].append(pattern)
                        
        except Exception as e:
            result["error"] = str(e)

        return result

    def _analyze_cluster_patterns(self, cluster_points: np.ndarray) -> Dict:
        """Analyze patterns within a cluster"""
        pattern = {
            "type": "Unknown",
            "confidence": 0.0,
            "description": "",
            "metrics": {}
        }

        try:
            if len(cluster_points) >= 2:
                correlation = np.corrcoef(cluster_points.T)[0,1]
                if abs(correlation) > 0.8:
                    pattern["type"] = "Linear"
                    pattern["confidence"] = abs(correlation)
                    pattern["description"] = f"Strong linear relationship (correlation: {correlation:.2f})"
                    pattern["metrics"]["correlation"] = float(correlation)
                    
            if len(cluster_points) >= 4:
                fft_vals = np.fft.fft(cluster_points[:,0])
                main_freq = np.abs(fft_vals[1:len(fft_vals)//2]).argmax() + 1
                if np.abs(fft_vals[main_freq]) > np.mean(np.abs(fft_vals)) * 2:
                    pattern["type"] = "Periodic"
                    pattern["confidence"] = 0.9
                    pattern["description"] = f"Periodic pattern detected with frequency {main_freq}"
                    pattern["metrics"]["frequency"] = int(main_freq)
                    
        except Exception as e:
            pattern["error"] = str(e)

        return pattern if pattern["type"] != "Unknown" else None

    def _generate_advanced_recommendations(self, analysis: Dict) -> None:
        """Generate comprehensive security recommendations"""
        recommendations = []

        # Add critical recommendations first
        if analysis["basic_vulnerabilities"]["reused_nonce"]:
            recommendations.append({
                "priority": "Critical",
                "title": "Nonce Reuse Detected",
                "description": "Immediate key rotation required",
                "actions": ["Generate new key pair", "Implement RFC 6979"]
            })

        if analysis["quantum_vulnerability"]["quantum_vulnerable"]:
            recommendations.append({
                "priority": "High",
                "title": "Quantum Vulnerability",
                "description": "Prepare for quantum threats",
                "actions": ["Plan migration to quantum-resistant algorithms"]
            })

        # Sort and store recommendations
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        recommendations.sort(key=lambda x: priority_order[x["priority"]])
        analysis["recommendations"] = recommendations

    def print_analysis_report(self, analysis: Dict[str, Any]) -> None:
        """Print a professionally formatted analysis report"""
        self.console.print("\n[bold cyan]╔══════════════════════════════════════════╗[/]")
        self.console.print("[bold cyan]║     ECDSA SIGNATURE SECURITY ANALYSIS    ║[/]")
        self.console.print("[bold cyan]╚══════════════════════════════════════════╝[/]\n")

        # Create vulnerability summary table
        vuln_table = Table(show_header=True, header_style="bold magenta", box=box.DOUBLE_EDGE)
        vuln_table.add_column("Vulnerability Type", style="cyan", width=30)
        vuln_table.add_column("Risk Level", style="yellow", width=15)
        vuln_table.add_column("Details", style="green", width=40)

        self._add_vulnerability_rows(vuln_table, analysis)
        self.console.print(vuln_table)

        self._print_detailed_analysis(analysis)
        self._print_recommendations(analysis['recommendations'])
        self._print_statistical_overview(analysis)
        self._generate_visualizations(analysis)

    def _add_vulnerability_rows(self, table: Table, analysis: Dict[str, Any]) -> None:
        """Add vulnerability findings to the table"""
        vulnerability_checks = [
            ("Hidden Number Problem", analysis['hidden_number_problem']),
            ("Lattice Attack", analysis['lattice_vulnerability']),
            ("Side Channel", analysis['side_channel_leakage']),
            ("Bleichenbacher", analysis['bleichenbacher_attack']),
            ("Prefix Lattice", analysis['prefix_lattice_attack']),
            ("Fault Injection", analysis['fault_injection']),
            ("Quantum", analysis['quantum_vulnerability']),
            ("Zero Value", analysis['zero_value_attack']),  # Changed from zero_value_vulnerability to zero_value_attack
            ("Timing Correlation", analysis['timing_correlation']),
            ("Entropy Patterns", analysis['entropy_analysis']),
            ("Modular Patterns", analysis['modular_arithmetic'])
        ]

        for vuln_type, vuln_data in vulnerability_checks:
            risk_level = self._determine_risk_level(vuln_data)
            details = self._format_vulnerability_details(vuln_data)
            
            row_style = self._get_risk_style(risk_level)
            table.add_row(vuln_type, risk_level, details, style=row_style)

    def _determine_risk_level(self, vuln_data: Dict) -> str:
        """Determine risk level from vulnerability data"""
        if isinstance(vuln_data, dict):
            if vuln_data.get('vulnerable', False) or vuln_data.get('vulnerable_to_hnp', False):
                return "Critical"
            if vuln_data.get('risk_level'):
                return vuln_data['risk_level']
        return "Low"

    def _get_risk_style(self, risk_level: str) -> str:
        """Get style based on risk level"""
        return {
            "Critical": "red",
            "High": "yellow",
            "Medium": "yellow",
            "Low": "green"
        }.get(risk_level, "white")

    def _format_vulnerability_details(self, vuln_data: Dict) -> str:
        """Format vulnerability details with clearer information"""
        if not isinstance(vuln_data, dict):
            return "Analysis data unavailable"
            
        if self._determine_risk_level(vuln_data) == "Critical":
            details = []
            
            # Quantum vulnerability - simplified to avoid duplication
            if vuln_data.get('quantum_vulnerable', False):
                details.append(f"Critical quantum vulnerability detected")
                details.append(f"Safety Score: {vuln_data.get('quantum_safety_score', 0)}/100")
                
            # Modular patterns - detailed analysis
            if vuln_data.get('modular_weakness', False):
                mod_details = []
                
                # Add pattern details
                patterns = vuln_data.get('patterns_detected', [])
                if patterns:
                    mod_details.append(f"Found {len(patterns)} vulnerable patterns")
                    
                # Add specific vulnerability types
                if 'exploitation_result' in vuln_data:
                    exploit_data = vuln_data['exploitation_result']
                    if isinstance(exploit_data, dict):
                        if 'type' in exploit_data:
                            mod_details.append(f"Type: {exploit_data['type']}")
                        if 'risk_assessment' in exploit_data:
                            risk = exploit_data['risk_assessment']
                            mod_details.append(f"Risk: {risk.get('severity', 'Unknown')}")
                        if 'estimated_complexity' in exploit_data:
                            complexity = exploit_data['estimated_complexity']
                            mod_details.append(f"Time: {complexity.get('time', 'Unknown')}")
                            mod_details.append(f"Success Rate: {complexity.get('success_rate', 'Unknown')}")

                # Add statistical analysis if available
                if 'statistical_analysis' in vuln_data:
                    stats = vuln_data['statistical_analysis']
                    if stats.get('anomalies'):
                        mod_details.append(f"Anomalies detected: {len(stats['anomalies'])}")

                details.extend(mod_details)

            if details:
                return " | ".join(details)
            return "Critical vulnerability detected - see detailed analysis"
            
        # For non-critical vulnerabilities
        details = []
        if vuln_data.get('details'):
            details.extend(str(d) for d in vuln_data['details'][:2])
        if vuln_data.get('confidence'):
            details.append(f"Confidence: {vuln_data['confidence']:.2f}")
        
        return " | ".join(details) if details else "No significant findings"

    def _print_detailed_analysis(self, analysis: Dict[str, Any]) -> None:
        """Print detailed analysis sections"""
        self.console.print("\n[bold cyan]Detailed Analysis[/]", justify="center")
        
        sections = [
            ("Quantum Analysis", self._format_quantum_analysis(analysis['quantum_vulnerability'])),
            ("Modular Pattern Analysis", self._format_modular_analysis(analysis['modular_arithmetic'])),
            ("Entropy Analysis", self._format_entropy_analysis(analysis['entropy_analysis'])),
            ("Side Channel Analysis", self._format_side_channel_analysis(analysis['side_channel_leakage'])),
            ("Machine Learning Analysis", self._format_ml_analysis(analysis.get('ml_based_analysis', {})))
        ]

        for title, content in sections:
            panel = Panel(content, title=title, border_style="cyan")
            self.console.print(panel)

    def _format_modular_analysis(self, mod_data: Dict) -> str:
        """Format modular pattern analysis details"""
        if not isinstance(mod_data, dict):
            return "No modular analysis data available"

        lines = []
        
        # Overall status
        lines.append(f"Modular Weakness Detected: {mod_data.get('modular_weakness', False)}")
        lines.append(f"Vulnerability Type: {mod_data.get('vulnerability_type', 'None')}")
        lines.append(f"Exploitation Difficulty: {mod_data.get('exploitation_difficulty', 'Unknown')}")
        
        # Pattern details
        patterns = mod_data.get('patterns_detected', [])
        if patterns:
            lines.append(f"\nDetected Patterns ({len(patterns)}):")
            for pattern in patterns[:3]:  # Show first 3 patterns
                lines.append(f"  • {pattern}")
            if len(patterns) > 3:
                lines.append(f"  ... and {len(patterns)-3} more patterns")

        # Exploitation details
        if 'exploitation_result' in mod_data:
            exploit = mod_data['exploitation_result']
            lines.append("\nExploitation Analysis:")
            lines.append(f"  Type: {exploit.get('type', 'Unknown')}")
            if 'risk_assessment' in exploit:
                risk = exploit['risk_assessment']
                lines.append(f"  Severity: {risk.get('severity', 'Unknown')}")
                lines.append(f"  Exploitability: {risk.get('exploitability', 'Unknown')}")
                lines.append(f"  Complexity: {risk.get('complexity', 'Unknown')}")
            if 'estimated_complexity' in exploit:
                complexity = exploit['estimated_complexity']
                lines.append(f"  Estimated Time: {complexity.get('time', 'Unknown')}")
                lines.append(f"  Success Rate: {complexity.get('success_rate', 'Unknown')}")

        # Statistical analysis
        if 'statistical_analysis' in mod_data:
            stats = mod_data['statistical_analysis']
            lines.append("\nStatistical Analysis:")
            if 'anomalies' in stats:
                lines.append(f"  Anomalies Found: {len(stats['anomalies'])}")
            if 'correlations' in stats:
                corr = stats['correlations']
                lines.append(f"  Value Correlation: {corr.get('r_s_correlation', 0):.2f}")

        return "\n".join(lines)
            
        # Check for critical conditions first
        if self._determine_risk_level(vuln_data) == "Critical":
            details = []
            
            # Bleichenbacher vulnerability details
            if vuln_data.get('vulnerable', False):
                biased_bits = len(vuln_data.get('biased_bits', []))
                details.append(f"Biased bits found: {biased_bits}")
                if 'estimated_complexity' in vuln_data:
                    details.append(f"Attack complexity: 2^{int(np.log2(vuln_data['estimated_complexity']))}")
                if 'attack_feasibility' in vuln_data:
                    details.append(f"Attack: {vuln_data['attack_feasibility']}")
                    
            # Hidden Number Problem details
            if vuln_data.get('vulnerable_to_hnp', False):
                details.append(f"Bits leaked: {vuln_data.get('bits_leaked', 0)}")
                if 'confidence' in vuln_data:
                    details.append(f"Confidence: {vuln_data['confidence']:.2f}")
                    
            # Side Channel details
            if vuln_data.get('timing_leakage', False) or vuln_data.get('power_leakage', False):
                if vuln_data.get('timing_leakage'):
                    details.append("Timing leakage detected")
                if vuln_data.get('power_leakage'):
                    details.append("Power analysis vulnerable")
                if 'vulnerability_score' in vuln_data:
                    details.append(f"Score: {vuln_data['vulnerability_score']:.2f}")
                    
            # Quantum vulnerability details
            if vuln_data.get('quantum_vulnerable', True):
                details.append(f"Qubits needed: {vuln_data.get('estimated_qubits', 'unknown')}")
                details.append(vuln_data.get('breaking_time_estimate', 'Time unknown'))
                
            # Zero value vulnerability details
            if vuln_data.get('zero_value_vulnerable', False):
                weak_patterns = len(vuln_data.get('weak_value_patterns', []))
                details.append(f"Weak patterns found: {weak_patterns}")
                
            # Modular arithmetic vulnerability details
            if vuln_data.get('modular_weakness', False):
                patterns = len(vuln_data.get('patterns_detected', []))
                details.append(f"Vulnerable patterns: {patterns}")
                if 'exploitation_difficulty' in vuln_data:
                    details.append(f"Exploitation: {vuln_data['exploitation_difficulty']}")

            if details:
                return " | ".join(details)
            return "Critical: Requires immediate attention"
            
        # For non-critical vulnerabilities
        details = []
        if vuln_data.get('details'):
            details.extend(str(d) for d in vuln_data['details'][:2])
        if vuln_data.get('confidence'):
            details.append(f"Confidence: {vuln_data['confidence']:.2f}")
        
        return " | ".join(details) if details else "No significant findings"

    def _determine_risk_level(self, vuln_data: Dict) -> str:
        """Determine risk level with improved critical detection"""
        if isinstance(vuln_data, dict):
            # Explicit critical conditions
            if vuln_data.get('vulnerable', False) and vuln_data.get('attack_feasibility') == "Practically Feasible":
                return "Critical"
            if vuln_data.get('vulnerable_to_hnp', False) and vuln_data.get('bits_leaked', 0) > 64:
                return "Critical"
            if vuln_data.get('timing_leakage', False) and vuln_data.get('vulnerability_score', 0) > 0.8:
                return "Critical"
            if vuln_data.get('quantum_vulnerable', False) and vuln_data.get('quantum_safety_score', 100) < 30:
                return "Critical"
            if vuln_data.get('zero_value_vulnerable', False) and vuln_data.get('risk_level') == "Critical":
                return "Critical"
            if vuln_data.get('modular_weakness', False) and vuln_data.get('exploitation_difficulty') == "Low":
                return "Critical"
                
            # Check general risk level
            if vuln_data.get('risk_level'):
                return vuln_data['risk_level']
                
        return "Low"


    def _print_detailed_analysis(self, analysis: Dict[str, Any]) -> None:
        """Print detailed analysis sections"""
        self.console.print("\n[bold cyan]Detailed Analysis[/]", justify="center")
        
        sections = [
            ("Quantum Analysis", self._format_quantum_analysis(analysis['quantum_vulnerability'])),
            ("Entropy Analysis", self._format_entropy_analysis(analysis['entropy_analysis'])),
            ("Side Channel Analysis", self._format_side_channel_analysis(analysis['side_channel_leakage'])),
            # Fixed ML analysis section to use the correct data
            ("Machine Learning Analysis", self._format_ml_analysis(analysis.get('ml_based_analysis', {})))
        ]

        for title, content in sections:
            panel = Panel(content, title=title, border_style="cyan")
            self.console.print(panel)

    def _format_ml_analysis(self, ml_data: Dict) -> str:
        """Format machine learning analysis data for display"""
        if not isinstance(ml_data, dict):
            return "No ML analysis data available"
            
        anomalies = ml_data.get('ml_anomalies', False)
        patterns = ml_data.get('detected_patterns', [])
        confidence = ml_data.get('prediction_confidence', 0.0)
        
        cluster_info = ml_data.get('cluster_analysis', {})
        num_clusters = cluster_info.get('num_clusters', 0)
        outliers = len(cluster_info.get('outliers', []))
        
        return (
            f"ML Anomalies Detected: {anomalies}\n"
            f"Number of Patterns: {len(patterns)}\n"
            f"Prediction Confidence: {confidence:.2f}\n"
            f"Clusters Found: {num_clusters}\n"
            f"Outliers Detected: {outliers}"
        )

    def _format_quantum_analysis(self, quantum_data: Dict) -> str:
        """Format quantum analysis data for display"""
        return (
            f"Quantum Vulnerability: {quantum_data['quantum_vulnerable']}\n"
            f"Required Qubits: {quantum_data['estimated_qubits']}\n"
            f"Breaking Time: {quantum_data['breaking_time_estimate']}\n"
            f"Safety Score: {quantum_data['quantum_safety_score']}/100"
        )

    def _format_entropy_analysis(self, entropy_data: Dict) -> str:
        """Format entropy analysis data for display"""
        return (
            f"Entropy Score: {entropy_data['entropy_score']:.2f}\n"
            f"Quality: {entropy_data['randomness_quality']}\n"
            f"Weak Patterns Found: {len(entropy_data.get('weak_patterns', []))}"
        )

    def _format_side_channel_analysis(self, side_channel_data: Dict) -> str:
        """Format side channel analysis data for display"""
        return (
            f"Timing Leakage: {side_channel_data['timing_leakage']}\n"
            f"Power Leakage: {side_channel_data['power_leakage']}\n"
            f"Cache Vulnerability: {side_channel_data['cache_vulnerability']}\n"
            f"Vulnerability Score: {side_channel_data['vulnerability_score']:.2f}"
        )

    def _format_ml_analysis(self, ml_data: Dict) -> str:
        """Format machine learning analysis data for display"""
        return (
            f"ML Anomalies: {ml_data.get('ml_anomalies', False)}\n"
            f"Detected Patterns: {len(ml_data.get('detected_patterns', []))}\n"
            f"Confidence: {ml_data.get('prediction_confidence', 0.0):.2f}"
        )

    def _generate_visualizations(self, analysis: Dict[str, Any]) -> None:
        """Generate visualizations for the analysis results"""
        plt.figure(figsize=(15, 10))
        
        # Plot 1: Signature Distribution
        plt.subplot(2, 2, 1)
        self._plot_signature_distribution(analysis)
        
        # Plot 2: Risk Assessment
        plt.subplot(2, 2, 2)
        self._plot_risk_assessment(analysis)
        
        # Plot 3: Timing Analysis
        plt.subplot(2, 2, 3)
        self._plot_timing_analysis(analysis)
        
        # Plot 4: Cluster Analysis
        plt.subplot(2, 2, 4)
        self._plot_cluster_analysis(analysis)
        
        plt.tight_layout()
        plt.savefig('ecdsa_analysis_report.png')
        plt.close()

    def _plot_signature_distribution(self, analysis: Dict) -> None:
        """Plot signature value distribution"""
        try:
            if 'nonce_analysis' in analysis and 'value_distribution' in analysis['nonce_analysis']:
                dist = analysis['nonce_analysis']['value_distribution']
                if 'histogram' in dist and 'bin_edges' in dist:
                    plt.hist(
                        dist['histogram'], 
                        bins=dist['bin_edges'], 
                        color='blue', 
                        alpha=0.7
                    )
                    plt.title('Signature Value Distribution')
                    plt.xlabel('Value Range')
                    plt.ylabel('Frequency')
            else:
                plt.text(0.5, 0.5, 'No distribution data available',
                        ha='center', va='center')
        except Exception as e:
            plt.text(0.5, 0.5, f'Error plotting distribution: {str(e)}',
                    ha='center', va='center')

    def _plot_risk_assessment(self, analysis: Dict) -> None:
        """Plot risk assessment summary"""
        try:
            vulnerabilities = []
            risk_levels = []
            
            for vuln_type, data in analysis.items():
                if isinstance(data, dict) and 'risk_level' in data:
                    vulnerabilities.append(vuln_type)
                    risk_levels.append(self._risk_level_to_numeric(data['risk_level']))
            
            if vulnerabilities:
                plt.barh(vulnerabilities, risk_levels, color='red', alpha=0.7)
                plt.title('Risk Assessment by Vulnerability Type')
                plt.xlabel('Risk Level (0-4)')
            else:
                plt.text(0.5, 0.5, 'No risk assessment data available',
                        ha='center', va='center')
        except Exception as e:
            plt.text(0.5, 0.5, f'Error plotting risk assessment: {str(e)}',
                    ha='center', va='center')

    def _plot_timing_analysis(self, analysis: Dict) -> None:
        """Plot timing analysis results"""
        try:
            if 'timing_correlation' in analysis:
                timing_data = analysis['timing_correlation']
                if 'correlation_patterns' in timing_data:
                    patterns = timing_data['correlation_patterns']
                    if patterns:
                        x = range(len(patterns))
                        correlations = [p.get('correlation', 0) for p in patterns]
                        plt.bar(x, correlations, color='green', alpha=0.7)
                        plt.title('Timing Correlation Patterns')
                        plt.xlabel('Pattern Index')
                        plt.ylabel('Correlation Strength')
                    else:
                        plt.text(0.5, 0.5, 'No timing patterns detected',
                                ha='center', va='center')
                else:
                    plt.text(0.5, 0.5, 'No timing correlation data available',
                            ha='center', va='center')
        except Exception as e:
            plt.text(0.5, 0.5, f'Error plotting timing analysis: {str(e)}',
                    ha='center', va='center')

    def _plot_cluster_analysis(self, analysis: Dict) -> None:
        """Plot cluster analysis results"""
        try:
            if 'ml_based_analysis' in analysis and 'cluster_analysis' in analysis['ml_based_analysis']:
                cluster_data = analysis['ml_based_analysis']['cluster_analysis']
                if 'cluster_sizes' in cluster_data and cluster_data['cluster_sizes']:
                    plt.pie(
                        cluster_data['cluster_sizes'],
                        labels=[f'Cluster {i}' for i in range(len(cluster_data['cluster_sizes']))],
                        autopct='%1.1f%%',
                        colors=plt.cm.Set3(np.linspace(0, 1, len(cluster_data['cluster_sizes']))),
                        startangle=90
                    )
                    plt.title('Signature Clusters Distribution')
                else:
                    plt.text(0.5, 0.5, 'No cluster data available',
                            ha='center', va='center')
            else:
                plt.text(0.5, 0.5, 'No cluster analysis data available',
                        ha='center', va='center')
        except Exception as e:
            plt.text(0.5, 0.5, f'Error plotting cluster analysis: {str(e)}',
                    ha='center', va='center')

    def _risk_level_to_numeric(self, risk_level: str) -> int:
        """Convert risk level string to numeric value"""
        return {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0
        }.get(risk_level, 0)


    def _print_recommendations(self, recommendations: List[Dict]) -> None:
        """Print security recommendations"""
        self.console.print("\n[bold red]Security Recommendations[/]", justify="center")
        
        if not recommendations:
            self.console.print("\n[yellow]No specific recommendations generated.[/]")
            return

        rec_table = Table(show_header=True, header_style="bold red", box=box.SIMPLE_HEAD)
        rec_table.add_column("Priority", style="cyan", width=10)
        rec_table.add_column("Title", style="yellow", width=30)
        rec_table.add_column("Description", style="white", width=40)
        rec_table.add_column("Actions", style="green", width=40)
        
        # Sort recommendations by priority
        priority_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        sorted_recommendations = sorted(
            recommendations,
            key=lambda x: priority_order.get(x.get('priority', 'Low'), 4)
        )

        for rec in sorted_recommendations:
            priority = rec.get('priority', 'Low')
            title = rec.get('title', 'N/A')
            description = rec.get('description', 'No description provided')
            
            # Format actions list
            actions = rec.get('actions', [])
            if isinstance(actions, list):
                action_text = "\n".join(f"• {action}" for action in actions)
            else:
                action_text = str(actions)

            # Style based on priority
            style = {
                "Critical": "red",
                "High": "yellow",
                "Medium": "cyan",
                "Low": "green"
            }.get(priority, "white")

            rec_table.add_row(
                priority,
                title,
                description,
                action_text,
                style=style
            )

        self.console.print(rec_table)

    def _print_statistical_overview(self, analysis: Dict[str, Any]) -> None:
        """Print statistical overview of the analysis with improved counting"""
        self.console.print("\n[bold cyan]Statistical Overview[/]", justify="center")
        
        stats = Table(show_header=True, header_style="bold blue", box=box.MINIMAL_DOUBLE_HEAD)
        stats.add_column("Metric", style="cyan")
        stats.add_column("Value", style="yellow")
        
        # Count vulnerabilities more accurately
        total_vulnerabilities = sum([
            1 for key, data in analysis.items()
            if isinstance(data, dict) and (
                data.get('vulnerable', False) or
                data.get('vulnerable_to_hnp', False) or
                data.get('vulnerable_to_prefix', False) or
                data.get('quantum_vulnerable', False) or
                data.get('modular_weakness', False) or
                data.get('zero_value_vulnerable', False) or
                data.get('timing_leakage', False) or
                data.get('power_leakage', False) or
                data.get('fault_vulnerable', False) or
                data.get('cache_vulnerability', False)
            )
        ])

        # Count critical issues more accurately
        critical_issues = sum([
            1 for key, data in analysis.items()
            if isinstance(data, dict) and self._determine_risk_level(data) == "Critical"
        ])
        
        # Calculate overall security score
        security_score = self._calculate_security_score(analysis)
        
        stats.add_row("Total Vulnerabilities Found", str(total_vulnerabilities))
        stats.add_row("Critical Issues", str(critical_issues))
        stats.add_row("Overall Security Score", f"{security_score}/100")
        
        self.console.print(stats)

    def _determine_risk_level(self, vuln_data: Dict) -> str:
        """Determine risk level with more accurate critical detection"""
        if isinstance(vuln_data, dict):
            # Bleichenbacher attack specific checks
            if 'vulnerable' in vuln_data and vuln_data['vulnerable']:
                if vuln_data.get('estimated_complexity', float('inf')) < 2**80:
                    return "Critical"
                if vuln_data.get('attack_feasibility') == "Practically Feasible":
                    return "Critical"

            # Quantum vulnerability check
            if vuln_data.get('quantum_vulnerable', False):
                if vuln_data.get('quantum_safety_score', 100) < 30:
                    return "Critical"
                return "Critical"  # All quantum vulnerabilities are critical

            # Modular arithmetic check
            if vuln_data.get('modular_weakness', False):
                if vuln_data.get('exploitation_difficulty') == "Low":
                    return "Critical"

            # Cache vulnerability check
            if vuln_data.get('cache_vulnerability', False):
                if vuln_data.get('vulnerability_score', 0) > 0.7:
                    return "Critical"

            # General risk level check
            if vuln_data.get('risk_level') == "Critical":
                return "Critical"

        return "Low"

    def _calculate_security_score(self, analysis: Dict[str, Any]) -> int:
        """Calculate overall security score with improved penalty system"""
        score = 100
        
        # Heavier penalties for critical vulnerabilities
        if analysis.get('quantum_vulnerability', {}).get('quantum_vulnerable', False):
            score -= 30
            
        if analysis.get('bleichenbacher_attack', {}).get('vulnerable', False):
            score -= 25
            
        if analysis.get('modular_arithmetic', {}).get('modular_weakness', False):
            if analysis['modular_arithmetic'].get('exploitation_difficulty') == "Low":
                score -= 25
            else:
                score -= 15

        # Additional penalties
        if analysis.get('lattice_vulnerability', {}).get('vulnerable_to_lattice', False):
            score -= 15
            
        if analysis.get('side_channel_leakage', {}).get('timing_leakage', False):
            score -= 10
            
        if analysis.get('entropy_analysis', {}).get('entropy_weakness', False):
            score -= 15
            
        # Count critical issues
        critical_count = sum(1 for _, data in analysis.items() 
                           if isinstance(data, dict) and 
                           self._determine_risk_level(data) == "Critical")
        
        # Additional penalty for multiple critical issues
        if critical_count > 1:
            score -= (critical_count - 1) * 10
            
        return max(0, score)  # Ensure score doesn't go below 0


def main():
    analyzer = ECDSAAdvancedAnalyzer()
    console = Console()
    
    console.print("[bold green]Starting ECDSA Security Analysis...[/]")
    
    # Generate test signatures
    signatures = []
    metadata = []
    private_key, _ = analyzer.generate_keypair()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Generating test data...", total=10)
        
        for i in range(10):
            k = (i * 1337 + 42) % analyzer.order
            signature = private_key.sign("Test message".encode(), k=k)
            r, s = util.sigdecode_string(signature, analyzer.order)
            signatures.append((signature, r, s))
            
            metadata.append(SignatureMetadata(
                timestamp=float(i),
                computation_time=random.uniform(0.1, 0.3),
                bit_length=256,
                entropy=random.uniform(0.8, 1.0)
            ))
            progress.update(task, advance=1)
    
    console.print("[bold green]Running comprehensive security analysis...[/]")
    analysis = analyzer.complete_signature_analysis(signatures, metadata)
    
    # Generate and print report
    analyzer.print_analysis_report(analysis)
    
    console.print("\n[bold green]Analysis complete! Detailed report has been generated.[/]")
    console.print("[bold yellow]Please review the recommendations carefully.[/]")

if __name__ == "__main__":
    main()

