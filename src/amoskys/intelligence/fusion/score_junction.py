"""
AMOSKYS Score Junction - Neural Fusion Engine
Multi-signal threat score fusion with adaptive weighting
Phase 2.5 - Neural Intelligence Core
"""

import logging
import numpy as np
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime
import json

logger = logging.getLogger(__name__)

@dataclass
class ThreatSignal:
    """Individual threat detection signal from various models/agents"""
    signal_id: str
    source: str  # Model or agent name
    confidence: float  # 0.0 to 1.0
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    signal_type: str  # ANOMALY, MALWARE, INTRUSION, etc.
    features: Dict[str, Any]
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class FusedThreatScore:
    """Final fused threat assessment"""
    flow_id: str
    final_score: float  # 0.0 to 1.0
    confidence: float  # Confidence in the final score
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    contributing_signals: List[ThreatSignal]
    fusion_metadata: Dict[str, Any]
    timestamp: datetime
    explanation: str
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API/dashboard"""
        return {
            'flow_id': self.flow_id,
            'final_score': self.final_score,
            'confidence': self.confidence,
            'risk_level': self.risk_level,
            'signal_count': len(self.contributing_signals),
            'timestamp': self.timestamp.isoformat(),
            'explanation': self.explanation,
            'fusion_metadata': self.fusion_metadata
        }

class ScoreJunction:
    """
    AMOSKYS Neural Score Junction
    
    Fuses multiple threat detection signals into a unified threat score
    using adaptive weighting and confidence calibration.
    
    This is the neural synapse where multiple weak signals
    combine into strong, explainable certainty.
    """
    
    def __init__(self, 
                 fusion_method: str = "weighted_average",
                 confidence_threshold: float = 0.5,
                 enable_adaptive_weights: bool = True):
        """
        Initialize Score Junction
        
        Args:
            fusion_method: Method for combining scores (weighted_average, max, bayesian)
            confidence_threshold: Minimum confidence threshold for alerts
            enable_adaptive_weights: Enable dynamic weight adjustment
        """
        self.fusion_method = fusion_method
        self.confidence_threshold = confidence_threshold
        self.enable_adaptive_weights = enable_adaptive_weights
        
        # Model performance tracking for adaptive weights
        self.model_performance = {}
        self.fusion_count = 0
        
        # Default model weights (can be learned over time)
        self.model_weights = {
            'xgboost_detector': 0.35,
            'lstm_detector': 0.25,
            'autoencoder_detector': 0.20,
            'flow_agent': 0.10,
            'proc_agent': 0.05,
            'syscall_agent': 0.05
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            'LOW': 0.3,
            'MEDIUM': 0.6,
            'HIGH': 0.8,
            'CRITICAL': 0.95
        }
        
    def fuse_signals(self, signals: List[ThreatSignal], flow_id: str) -> FusedThreatScore:
        """
        Fuse multiple threat signals into unified score
        
        Args:
            signals: List of threat signals from various sources
            flow_id: Unique flow identifier
            
        Returns:
            FusedThreatScore: Unified threat assessment
        """
        logger.debug(f"🧠 Fusing {len(signals)} signals for flow {flow_id}")
        
        if not signals:
            return self._create_benign_score(flow_id)
        
        # Calculate fused score based on method
        if self.fusion_method == "weighted_average":
            final_score, confidence = self._weighted_average_fusion(signals)
        elif self.fusion_method == "max":
            final_score, confidence = self._max_fusion(signals)
        elif self.fusion_method == "bayesian":
            final_score, confidence = self._bayesian_fusion(signals)
        else:
            raise ValueError(f"Unknown fusion method: {self.fusion_method}")
        
        # Determine risk level
        risk_level = self._calculate_risk_level(final_score)
        
        # Generate explanation
        explanation = self._generate_explanation(signals, final_score, risk_level)
        
        # Create fusion metadata
        fusion_metadata = {
            'fusion_method': self.fusion_method,
            'signal_sources': [s.source for s in signals],
            'signal_count': len(signals),
            'weights_used': {s.source: self.model_weights.get(s.source, 0.1) for s in signals},
            'highest_signal': max(signals, key=lambda x: x.confidence).confidence,
            'signal_variance': np.var([s.confidence for s in signals])
        }
        
        self.fusion_count += 1
        
        return FusedThreatScore(
            flow_id=flow_id,
            final_score=final_score,
            confidence=confidence,
            risk_level=risk_level,
            contributing_signals=signals,
            fusion_metadata=fusion_metadata,
            timestamp=datetime.now(),
            explanation=explanation
        )
    
    def _weighted_average_fusion(self, signals: List[ThreatSignal]) -> Tuple[float, float]:
        """
        Weighted average fusion of threat signals
        
        Args:
            signals: List of threat signals
            
        Returns:
            Tuple[float, float]: (fused_score, confidence)
        """
        weighted_sum = 0.0
        total_weight = 0.0
        confidence_sum = 0.0
        
        for signal in signals:
            weight = self.model_weights.get(signal.source, 0.1)
            weighted_sum += signal.confidence * weight
            total_weight += weight
            confidence_sum += signal.confidence
        
        if total_weight == 0:
            return 0.0, 0.0
        
        fused_score = weighted_sum / total_weight
        
        # Confidence based on signal agreement and individual confidences
        avg_confidence = confidence_sum / len(signals)
        signal_variance = np.var([s.confidence for s in signals])
        confidence = avg_confidence * (1.0 - signal_variance)  # Lower if signals disagree
        
        return fused_score, min(confidence, 1.0)
    
    def _max_fusion(self, signals: List[ThreatSignal]) -> Tuple[float, float]:
        """
        Maximum score fusion (conservative approach)
        
        Args:
            signals: List of threat signals
            
        Returns:
            Tuple[float, float]: (fused_score, confidence)
        """
        max_signal = max(signals, key=lambda x: x.confidence)
        return max_signal.confidence, max_signal.confidence
    
    def _bayesian_fusion(self, signals: List[ThreatSignal]) -> Tuple[float, float]:
        """
        Bayesian probability fusion
        
        Args:
            signals: List of threat signals
            
        Returns:
            Tuple[float, float]: (fused_score, confidence)
        """
        # Convert confidence scores to probabilities
        threat_prob = 1.0
        benign_prob = 1.0
        
        for signal in signals:
            p_threat = signal.confidence
            p_benign = 1.0 - signal.confidence
            
            threat_prob *= p_threat
            benign_prob *= p_benign
        
        # Normalize probabilities
        total_prob = threat_prob + benign_prob
        if total_prob == 0:
            return 0.5, 0.0
        
        final_threat_prob = threat_prob / total_prob
        
        # Confidence based on how decisive the probability is
        confidence = abs(final_threat_prob - 0.5) * 2.0
        
        return final_threat_prob, confidence
    
    def _calculate_risk_level(self, score: float) -> str:
        """
        Calculate risk level based on threat score
        
        Args:
            score: Threat score (0.0 to 1.0)
            
        Returns:
            str: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        if score >= self.risk_thresholds['CRITICAL']:
            return 'CRITICAL'
        elif score >= self.risk_thresholds['HIGH']:
            return 'HIGH'
        elif score >= self.risk_thresholds['MEDIUM']:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_explanation(self, signals: List[ThreatSignal], 
                            final_score: float, risk_level: str) -> str:
        """
        Generate human-readable explanation of threat assessment
        
        Args:
            signals: Contributing threat signals
            final_score: Final fused score
            risk_level: Calculated risk level
            
        Returns:
            str: Human-readable explanation
        """
        if not signals:
            return "No threat signals detected. Flow appears benign."
        
        # Identify primary contributors
        top_signals = sorted(signals, key=lambda x: x.confidence, reverse=True)[:3]
        
        explanation_parts = [
            f"Threat assessment: {risk_level} risk (score: {final_score:.3f})"
        ]
        
        if len(signals) == 1:
            signal = signals[0]
            explanation_parts.append(
                f"Single detection from {signal.source} "
                f"({signal.signal_type}, confidence: {signal.confidence:.3f})"
            )
        else:
            explanation_parts.append(
                f"Fused from {len(signals)} detection signals:"
            )
            
            for i, signal in enumerate(top_signals):
                explanation_parts.append(
                    f"  {i+1}. {signal.source}: {signal.signal_type} "
                    f"(confidence: {signal.confidence:.3f})"
                )
        
        # Add specific threat indicators if available
        threat_types = set(s.signal_type for s in signals)
        if len(threat_types) > 1:
            explanation_parts.append(
                f"Multiple threat types detected: {', '.join(threat_types)}"
            )
        
        return " | ".join(explanation_parts)
    
    def _create_benign_score(self, flow_id: str) -> FusedThreatScore:
        """
        Create benign assessment when no signals are present
        
        Args:
            flow_id: Flow identifier
            
        Returns:
            FusedThreatScore: Benign assessment
        """
        return FusedThreatScore(
            flow_id=flow_id,
            final_score=0.0,
            confidence=0.9,  # High confidence in benign assessment
            risk_level='LOW',
            contributing_signals=[],
            fusion_metadata={'fusion_method': 'no_signals'},
            timestamp=datetime.now(),
            explanation="No threat signals detected. Flow appears benign."
        )
    
    def update_model_weights(self, model_name: str, performance_score: float):
        """
        Update model weights based on performance feedback
        
        Args:
            model_name: Name of the model/agent
            performance_score: Performance score (0.0 to 1.0)
        """
        if self.enable_adaptive_weights:
            if model_name not in self.model_performance:
                self.model_performance[model_name] = []
            
            self.model_performance[model_name].append(performance_score)
            
            # Update weight based on recent performance
            recent_performance = np.mean(self.model_performance[model_name][-10:])
            self.model_weights[model_name] = recent_performance
            
            logger.info(f"🔧 Updated weight for {model_name}: {recent_performance:.3f}")
    
    def get_statistics(self) -> Dict:
        """Get fusion statistics"""
        return {
            'total_fusions': self.fusion_count,
            'model_weights': self.model_weights.copy(),
            'fusion_method': self.fusion_method,
            'confidence_threshold': self.confidence_threshold,
            'model_performance_history': {
                k: len(v) for k, v in self.model_performance.items()
            }
        }

# Testing and example usage
if __name__ == "__main__":
    # Create example threat signals
    signals = [
        ThreatSignal(
            signal_id="sig_001",
            source="xgboost_detector",
            confidence=0.85,
            severity="HIGH",
            signal_type="MALWARE",
            features={"suspicious_port": 4444},
            timestamp=datetime.now(),
            metadata={"model_version": "1.0"}
        ),
        ThreatSignal(
            signal_id="sig_002", 
            source="lstm_detector",
            confidence=0.72,
            severity="MEDIUM",
            signal_type="ANOMALY",
            features={"unusual_timing": True},
            timestamp=datetime.now(),
            metadata={"sequence_length": 100}
        ),
        ThreatSignal(
            signal_id="sig_003",
            source="flow_agent",
            confidence=0.65,
            severity="MEDIUM", 
            signal_type="INTRUSION",
            features={"port_scan": True},
            timestamp=datetime.now(),
            metadata={"agent_version": "2.4"}
        )
    ]
    
    # Test fusion
    junction = ScoreJunction()
    
    fused_score = junction.fuse_signals(signals, "flow_12345")
    
    print("🧠 AMOSKYS Score Junction Test")
    print("=" * 50)
    print(f"Flow ID: {fused_score.flow_id}")
    print(f"Final Score: {fused_score.final_score:.3f}")
    print(f"Confidence: {fused_score.confidence:.3f}")
    print(f"Risk Level: {fused_score.risk_level}")
    print(f"Contributing Signals: {len(fused_score.contributing_signals)}")
    print(f"Explanation: {fused_score.explanation}")
    print("\n📊 Fusion Metadata:")
    print(json.dumps(fused_score.fusion_metadata, indent=2))
    
    # Test adaptive weights
    junction.update_model_weights("xgboost_detector", 0.95)
    print(f"\n🔧 Updated Statistics:")
    print(json.dumps(junction.get_statistics(), indent=2))
