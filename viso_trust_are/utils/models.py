from datetime import datetime
from enum import Enum
from typing import List, Optional, Union
from pydantic import BaseModel


class PublicRelationshipSearchInput(BaseModel):
    """PublicRelationshipSearchInput Model."""

    name: str
    domains: list[str]


class ContextType(BaseModel):
    """ContextType Model"""

    name: Optional[str] = None


class DataType(BaseModel):
    """DataType Model."""

    name: Optional[str] = None


class RelationshipCreateUpdateInput(BaseModel):
    """RelationshipCreateUpdateInput Model."""

    id: Optional[int] = None
    name: str
    homepage: str
    description: Optional[str] = None
    contextTypes: Optional[List[ContextType]] = None
    dataTypes: Optional[List[DataType]] = None
    businessOwnerEmail: str
    tags: Optional[List[str]] = None


class Status(Enum):
    """Status Model."""

    NOT_ASSESSED = "NOT_ASSESSED"
    STARTED = "STARTED"
    REVIEW_STARTED = "REVIEW_STARTED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    COLLECTING_INFORMATION = "COLLECTING_INFORMATION"


class AssessmentStatusHistory(BaseModel):
    """AssessmentStatusHistory Model."""

    date: Optional[datetime] = None
    status: Optional[Status] = None


class PrimaryContact(BaseModel):
    """PrimaryContact Model."""

    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[str] = None


class Status2(Enum):
    """Status2 Model."""

    DELETED = "DELETED"
    NOT_ONBOARDED = "NOT_ONBOARDED"
    ONBOARDED = "ONBOARDED"


class RecertificationType(Enum):
    """RecertificationType Model."""

    MANUAL = "MANUAL"
    AUTOMATIC = "AUTOMATIC"
    NONE = "NONE"


class ResidualRisk(Enum):
    """ResidualRisk Model."""

    NO_ACCESS = "NO_ACCESS"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    EXTREME = "EXTREME"


class PotentialRisk(Enum):
    """PotentialRisk Model."""

    NO_ACCESS = "NO_ACCESS"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    EXTREME = "EXTREME"


class VisoUser(BaseModel):
    """VisoUser Model."""

    firstName: Optional[str] = None
    lastName: Optional[str] = None
    email: Optional[str] = None


class TagsCreateInput(BaseModel):
    """TagsCreateInput Model."""

    tags: List[str]


class CCLTag(str, Enum):
    """CCLTag Model."""

    UNKNOWN = "CCI Unknown"
    POOR = "CCI Poor"
    LOW = "CCI Low"
    MEDIUM = "CCI Medium"
    HIGH = "CCI High"
    EXCELLENT = "CCI Excellent"


CCL_THRESHOLDS = (
    (49, CCLTag.POOR),
    (59, CCLTag.LOW),
    (74, CCLTag.MEDIUM),
    (89, CCLTag.HIGH),
)


class Assessment(BaseModel):
    """Assessment Model."""

    status: Optional[Status] = None
    statusHistories: Optional[List[AssessmentStatusHistory]] = None
    completedDate: Optional[datetime] = None
    updatedDate: Optional[datetime] = None
    phaseDate: Optional[datetime] = None
    assessmentType: Optional[str] = None
    expirationDate: Optional[datetime] = None
    sentToEmail: Optional[str] = None
    createdDate: Optional[datetime] = None
    sentToFirstName: Optional[str] = None
    sentToLastName: Optional[str] = None
    sentBy: Optional[VisoUser] = None
    type: str


class CertificationAssessment(Assessment):
    """CertificationAssessment Model."""

    pass


class RecertificationAssessment(Assessment):
    """RecertificationAssessment Model."""

    pass


class ArtifactUpdateAssessment(Assessment):
    """ArtifactUpdateAssessment Model."""

    pass


class Relationship(BaseModel):
    """Relationship Model."""

    name: str
    id: Optional[int] = None
    status: Optional[Status2] = None
    tags: Optional[List[str]] = None
    primaryContact: Optional[PrimaryContact] = None
    recertificationType: Optional[RecertificationType] = None
    description: Optional[str] = None
    isTransitional: Optional[bool] = None
    assessments: Optional[
        List[
            Union[
                ArtifactUpdateAssessment,
                CertificationAssessment,
                RecertificationAssessment,
            ]
        ]
    ] = None
    updatedDate: Optional[datetime] = None
    residualRisk: Optional[ResidualRisk] = None
    subscribers: Optional[List[VisoUser]] = None
    homepage: Optional[str] = None
    dataTypes: Optional[List[DataType]] = None
    contextTypes: Optional[List[ContextType]] = None
    potentialRisk: Optional[PotentialRisk] = None
    createdDate: Optional[datetime] = None
    businessOwner: Optional[VisoUser] = None
    recertificationDate: Optional[datetime] = None
