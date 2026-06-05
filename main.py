import os
import re
from typing import List, Dict, Optional
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

load_dotenv(override=True)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_url = URL.create(
    drivername="postgresql",
    username=os.getenv("DB_USER"),
    password=os.getenv("DB_PASSWORD"),
    host=os.getenv("DB_HOST"),
    port=os.getenv("DB_PORT"),
    database=os.getenv("DB_NAME")
)
engine = create_engine(db_url)


def ensure_user_reports_table():
    """Create the user report table required by /api/reports if it is missing."""
    ddl = text("""
        CREATE TABLE IF NOT EXISTS user_reports (
            id SERIAL PRIMARY KEY,
            geom geometry(Point, 4326) NOT NULL,
            categories TEXT[] NOT NULL,
            intensity INTEGER NOT NULL DEFAULT 0 CHECK (intensity BETWEEN 0 AND 8),
            memo TEXT,
            etc_text TEXT,
            status TEXT NOT NULL DEFAULT 'visible' CHECK (status IN ('visible', 'hidden')),
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS idx_user_reports_geom
            ON user_reports USING GIST (geom);

        CREATE INDEX IF NOT EXISTS idx_user_reports_status_created_at
            ON user_reports (status, created_at DESC);
    """)
    with engine.begin() as conn:
        conn.execute(ddl)


@app.on_event("startup")
def on_startup():
    ensure_user_reports_table()


class RouteRequest(BaseModel):
    start_lat: float
    start_lng: float
    end_lat: float
    end_lng: float
    persona: str
    request_hour: int

# 사용자 제보 유형 (피그마 디자인 7종)
REPORT_CATEGORIES = [
    "도로 파손", "어두운 골목", "가로등/조도 불량", "공사 중",
    "CCTV 사각지대", "경사도", "기타",
]

class ReportRequest(BaseModel):
    lat: float
    lng: float
    categories: List[str]          # 체크된 유형(복수 선택 가능)
    intensity: int = 0             # 체감 위험 강도 0~8
    memo: Optional[str] = None     # 한마디(선택)
    etc_text: Optional[str] = None # '기타' 선택 시 직접 입력한 유형 문구

class ReportStatusRequest(BaseModel):
    status: str                    # 'visible' | 'hidden'

# 관리자(제보 감독) 키. 시연 편의를 위한 기본값이며, 운영 시 .env의 ADMIN_KEY로 override.
ADMIN_KEY = os.getenv("ADMIN_KEY") or "safemap-admin-2026"

def require_admin(x_admin_key: Optional[str]):
    """관리자 키 검증. 헤더 X-Admin-Key 가 .env ADMIN_KEY 와 일치해야 통과."""
    if not ADMIN_KEY:
        raise HTTPException(status_code=500, detail="서버에 ADMIN_KEY가 설정되지 않았습니다.")
    if x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="관리자 인증 실패")

def clean_text(text_data: str) -> str:
    if not text_data: return ""
    text_data = text_data.replace('\n', ' ').replace('\r', ' ')
    text_data = re.sub(r'[.,\s]+$', '', text_data)
    return re.sub(r'\s+', ' ', text_data).strip()

@app.post("/api/routes/safe-path")
def get_safe_path(request: RouteRequest):
    weights = {
        "general": {"sec": 1.0, "led": 1.0, "sdot": 1.0, "slp": 1.0, "civ": 1.0, "flow": 1.0},
        "women":   {"sec": 2.5, "led": 1.5, "sdot": 2.2, "slp": 1.0, "civ": 1.2, "flow": 1.8},
        "senior":  {"sec": 1.0, "led": 1.2, "sdot": 1.2, "slp": 5.0, "civ": 1.5, "flow": 1.0}
    }
    w = weights.get(request.persona.lower(), weights["general"])
    w_sum = w["sec"] + w["led"] + w["sdot"] + w["slp"] + w["civ"] + w["flow"]

    try:
        query = text("""
        WITH start_node AS (
            SELECT id FROM road_links_vertices_pgr
            ORDER BY the_geom <-> ST_SetSRID(ST_MakePoint(:start_lng, :start_lat), 4326) LIMIT 1
        ),
        end_node AS (
            SELECT id FROM road_links_vertices_pgr
            ORDER BY the_geom <-> ST_SetSRID(ST_MakePoint(:end_lng, :end_lat), 4326) LIMIT 1
        ),
        path_edges AS (
            SELECT p.seq, p.edge, r.geometry, r.security_risk_score, r.led_risk_score, r.slope_risk_score, r.civil_risk_score, r.flow_risk_score, r.length,
                   COALESCE(s.light_risk, 0.5) AS sdot_risk_score
            FROM pgr_dijkstra(
                'SELECT r.id, r.source, r.target,
                    (r.length * (1 +
                        r.security_risk_score * :w_sec +
                        r.led_risk_score * :w_led +
                        COALESCE(s.light_risk, 0.5) * :w_sdot +
                        r.slope_risk_score * :w_slp +
                        r.civil_risk_score * :w_civ +
                        r.flow_risk_score * :w_flow
                    )) AS cost
                 FROM road_links r
                 LEFT JOIN sdot_light s ON r.nearest_sdot_id = s.sensor_id AND s.hour = :req_hour',
                (SELECT id FROM start_node),
                (SELECT id FROM end_node),
                directed := false
            ) AS p
            JOIN road_links AS r ON p.edge = r.id
            LEFT JOIN sdot_light s ON r.nearest_sdot_id = s.sensor_id AND s.hour = :req_hour
            WHERE p.edge > 0
        ),
        edge_features AS (
            SELECT *,
                CASE
                    WHEN edge_risk < 0.52 THEN 'safe'
                    WHEN edge_risk < 0.64 THEN 'caution'
                    WHEN edge_risk < 0.78 THEN 'warning'
                    ELSE 'danger'
                END AS risk_level,
                CASE
                    WHEN c_max = c_sec  THEN 'security'
                    WHEN c_max = c_led  THEN 'led'
                    WHEN c_max = c_sdot THEN 'sdot'
                    WHEN c_max = c_slp  THEN 'slope'
                    WHEN c_max = c_civ  THEN 'civil'
                    ELSE 'flow'
                END AS dominant_factor,
                c_max / NULLIF(c_sec + c_led + c_sdot + c_slp + c_civ + c_flow, 0) AS dominant_ratio
            FROM (
                SELECT *,
                    security_risk_score * :w_sec AS c_sec,
                    led_risk_score * :w_led AS c_led,
                    sdot_risk_score * :w_sdot AS c_sdot,
                    slope_risk_score * :w_slp AS c_slp,
                    civil_risk_score * :w_civ AS c_civ,
                    flow_risk_score * :w_flow AS c_flow,
                    GREATEST(
                        security_risk_score * :w_sec, led_risk_score * :w_led, sdot_risk_score * :w_sdot,
                        slope_risk_score * :w_slp, civil_risk_score * :w_civ, flow_risk_score * :w_flow
                    ) AS c_max,
                    (security_risk_score * :w_sec
                     + led_risk_score * :w_led
                     + sdot_risk_score * :w_sdot
                     + slope_risk_score * :w_slp
                     + civil_risk_score * :w_civ
                     + flow_risk_score * :w_flow) / :w_sum AS edge_risk
                FROM path_edges
            ) scored
        ),
        nearby_risks AS (
            SELECT DISTINCT c.category, c.contents, ST_Y(c.geometry::geometry) AS lat, ST_X(c.geometry::geometry) AS lng
            FROM civil_risk_points c
            JOIN path_edges e ON ST_DWithin(c.geometry::geography, e.geometry::geography, 20)
        )
        SELECT
            (SELECT COALESCE(json_agg(json_build_object(
                'type', 'Feature',
                'geometry', ST_AsGeoJSON(geometry)::json,
                'properties', json_build_object(
                    'seq', seq,
                    'edge_risk', round(edge_risk::numeric, 3),
                    'risk_level', risk_level,
                    'dominant_factor', dominant_factor,
                    'dominant_ratio', round(dominant_ratio::numeric, 3),
                    'slope_risk', round(slope_risk_score::numeric, 3),
                    'length', round(length::numeric, 2)
                )
            ) ORDER BY seq), '[]') FROM edge_features) AS features,
            SUM(e.length) AS total_distance,
            COALESCE(SUM(e.security_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_sec,
            COALESCE(SUM(e.led_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_led,
            COALESCE(SUM(e.sdot_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_sdot,
            COALESCE(SUM(e.slope_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_slp,
            COALESCE(SUM(e.civil_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_civ,
            COALESCE(SUM(e.flow_risk_score * e.length) / NULLIF(SUM(e.length), 0), 0) AS avg_flow,
            (SELECT COALESCE(json_agg(json_build_object('type', category, 'detail', contents, 'lat', lat, 'lng', lng)), '[]') FROM nearby_risks) AS detected_points
        FROM edge_features e;
        """)

        with engine.connect() as conn:
            result = conn.execute(query, {
                "start_lng": request.start_lng, "start_lat": request.start_lat,
                "end_lng": request.end_lng, "end_lat": request.end_lat,
                "req_hour": request.request_hour,
                "w_sec": w["sec"], "w_led": w["led"], "w_sdot": w["sdot"], "w_slp": w["slp"], "w_civ": w["civ"],
                "w_flow": w["flow"], "w_sum": w_sum
            }).fetchone()

        if not result or not result[0]:
            raise HTTPException(status_code=404, detail="경로를 찾을 수 없습니다.")

        # 데이터 파싱
        features = result[0] or []
        dist = round(result[1], 2)
        # avg_flow 까지 6개의 위험도 추출
        avg_sec, avg_led, avg_sdot, avg_slp, avg_civ, avg_flow = [round(v, 3) for v in result[2:8]]
        markers = [ {**m, "detail": clean_text(m['detail']), "type": clean_text(m['type'])} for m in (result[8] or []) ]

        # 인사이트 생성 로직
        insights = []
        headers = {"women": "✅ [여성 안심]", "senior": "✅ [노약자 맞춤]", "general": "✅ [일반 추천]"}
        insights.append(headers.get(request.persona.lower(), headers["general"]))

        light_msg = ""
        if avg_led <= 0.3: light_msg += "가로등이 촘촘하게 설치되어 있으며, "
        else: light_msg += "가로등 배치가 다소 드문 구간이 포함되어 있으며, "

        if avg_sdot <= 0.3: light_msg += f"{request.request_hour}시 현재 실제 측정 조도가 매우 밝습니다."
        else: light_msg += f"{request.request_hour}시 현재 센서 조도가 다소 낮아 보행 시 주의가 필요합니다."
        insights.append(light_msg)

        if avg_sec <= 0.4: insights.append("CCTV 밀집 구역을 우선 경유합니다.")
        if avg_slp >= 0.6: insights.append("경사가 급한 오르막/계단 구간이 있으니 참고 바랍니다.")
        
        if avg_flow <= 0.4:
            insights.append("주변 유동 인구가 적절히 확보되어 야간에도 고립감이 덜한 경로입니다.")
        elif avg_flow >= 0.7:
            insights.append("인적이 상대적으로 드문 구간이 일부 포함되어 있습니다.")

        if markers:
            risk_types = list(set([m['type'] for m in markers]))
            insights.append(f"실시간으로 감지된 '{', '.join(risk_types[:2])}' 등의 요소를 알고리즘에 반영하였습니다.")

        return {
            "status": "success",
            "persona_applied": request.persona,
            "request_hour": request.request_hour,
            "total_distance_meters": dist,
            "route_analysis": {
                "summary": " ".join(insights),
                "scores": {
                    "infrastructure_led": avg_led,
                    "realtime_sdot_light": avg_sdot,
                    "security_cctv": avg_sec,
                    "slope": avg_slp,
                    "civil_complaint": avg_civ,
                    "floating_population": avg_flow 
                },
                "markers": markers
            },
            "geojson": {"type": "FeatureCollection", "features": features}
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/api/map/cctv")
def get_cctv_locations(lat: float = None, lng: float = None, radius: float = 1000):
    """
    프론트엔드 지도에 표시할 CCTV 위치 데이터를 반환하는 엔드포인트
    lat, lng, radius(미터) 파라미터로 반경 필터링 가능
    """
    try:
        if lat is not None and lng is not None:
            # 좌표가 있으면 반경 내 CCTV만 조회
            query = text("""
                SELECT 
                    id, 
                    latitude AS lat, 
                    longitude AS lng 
                FROM cctv_cameras
                WHERE ST_DWithin(
                    geom,
                    ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)::geography,
                    :radius
                )
                LIMIT 50
            """)
            params = {"lat": lat, "lng": lng, "radius": radius}
        else:
            # 좌표 없으면 전체 반환 (기존 동작 유지)
            query = text("""
                SELECT id, latitude AS lat, longitude AS lng
                FROM cctv_cameras
            """)
            params = {}

        with engine.connect() as conn:
            result = conn.execute(query, params).fetchall()
            cctv_list = [
                {"id": row[0], "lat": row[1], "lng": row[2]}
                for row in result
            ]

        return {
            "status": "success",
            "count": len(cctv_list),
            "data": cctv_list
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"CCTV 데이터 조회 오류: {str(e)}")


@app.post("/api/reports")
def create_report(report: ReportRequest):
    """
    사용자 위험 제보 등록 (실시간 DB 반영).
    ※ 신뢰도 검증 문제로 위험도(라우팅) 계산에는 반영하지 않고,
       지도 별도 마커 + 경로 참고정보로만 사용한다.
    """
    # 유형 검증: 허용된 7종만, 빈 값 제거
    cats = [c.strip() for c in report.categories if c and c.strip()]
    invalid = [c for c in cats if c not in REPORT_CATEGORIES]
    if invalid:
        raise HTTPException(status_code=400, detail=f"허용되지 않은 제보 유형: {invalid}")
    if not cats:
        raise HTTPException(status_code=400, detail="제보 유형을 1개 이상 선택해주세요.")

    intensity = max(0, min(8, int(report.intensity)))  # 0~8 범위 보호
    memo = clean_text(report.memo) if report.memo else None
    # '기타' 직접 입력 문구: '기타'를 선택했을 때만 의미가 있음
    etc_text = clean_text(report.etc_text) if report.etc_text else None
    if "기타" not in cats:
        etc_text = None

    try:
        query = text("""
            INSERT INTO user_reports (geom, categories, intensity, memo, etc_text)
            VALUES (ST_SetSRID(ST_MakePoint(:lng, :lat), 4326), :cats, :intensity, :memo, :etc_text)
            RETURNING id, ST_Y(geom) AS lat, ST_X(geom) AS lng,
                      categories, intensity, memo, etc_text, created_at
        """)
        with engine.begin() as conn:
            row = conn.execute(query, {
                "lng": report.lng, "lat": report.lat,
                "cats": cats, "intensity": intensity, "memo": memo, "etc_text": etc_text,
            }).fetchone()

        return {
            "status": "success",
            "data": {
                "id": row[0], "lat": row[1], "lng": row[2],
                "categories": list(row[3]), "intensity": row[4],
                "memo": row[5], "etc_text": row[6], "created_at": row[7].isoformat(),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"제보 등록 오류: {str(e)}")


@app.get("/api/reports")
def get_reports(lat: float = None, lng: float = None, radius: float = 1000, limit: int = 200):
    """
    지도 마커용 사용자 제보 조회.
    lat/lng/radius(미터)로 반경 필터링, 없으면 최신순 전체(limit).
    """
    try:
        if lat is not None and lng is not None:
            query = text("""
                SELECT id, ST_Y(geom) AS lat, ST_X(geom) AS lng,
                       categories, intensity, memo, etc_text, created_at
                FROM user_reports
                WHERE status = 'visible'
                  AND ST_DWithin(geom::geography,
                                 ST_SetSRID(ST_MakePoint(:lng, :lat), 4326)::geography, :radius)
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            params = {"lat": lat, "lng": lng, "radius": radius, "limit": limit}
        else:
            query = text("""
                SELECT id, ST_Y(geom) AS lat, ST_X(geom) AS lng,
                       categories, intensity, memo, etc_text, created_at
                FROM user_reports
                WHERE status = 'visible'
                ORDER BY created_at DESC
                LIMIT :limit
            """)
            params = {"limit": limit}

        with engine.connect() as conn:
            rows = conn.execute(query, params).fetchall()

        data = [{
            "id": r[0], "lat": r[1], "lng": r[2],
            "categories": list(r[3]), "intensity": r[4],
            "memo": r[5], "etc_text": r[6], "created_at": r[7].isoformat(),
        } for r in rows]

        return {"status": "success", "count": len(data), "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"제보 조회 오류: {str(e)}")


# ─────────────────────────────────────────────
# 관리자(제보 감독) API — 모두 X-Admin-Key 헤더 필요
#  · 신뢰도 낮은/부적절 제보를 숨김(소프트 삭제) 처리하거나 영구 삭제
#  · 숨김 처리는 기록을 남겨 감사/복구가 가능 (위험도 계산엔 애초에 미반영)
# ─────────────────────────────────────────────
@app.get("/api/admin/reports")
def admin_list_reports(x_admin_key: Optional[str] = Header(None), limit: int = 500):
    """관리자용 전체 제보 목록 (숨김 포함). 최신순."""
    require_admin(x_admin_key)
    try:
        query = text("""
            SELECT id, ST_Y(geom) AS lat, ST_X(geom) AS lng,
                   categories, intensity, memo, etc_text, status, created_at
            FROM user_reports
            ORDER BY created_at DESC
            LIMIT :limit
        """)
        with engine.connect() as conn:
            rows = conn.execute(query, {"limit": limit}).fetchall()
        data = [{
            "id": r[0], "lat": r[1], "lng": r[2],
            "categories": list(r[3]), "intensity": r[4],
            "memo": r[5], "etc_text": r[6], "status": r[7],
            "created_at": r[8].isoformat(),
        } for r in rows]
        return {"status": "success", "count": len(data), "data": data}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"관리자 조회 오류: {str(e)}")


@app.patch("/api/admin/reports/{report_id}")
def admin_set_report_status(report_id: int, body: ReportStatusRequest,
                            x_admin_key: Optional[str] = Header(None)):
    """제보 노출 상태 변경 (visible ↔ hidden). 소프트 삭제 = hidden."""
    require_admin(x_admin_key)
    new_status = (body.status or "").strip()
    if new_status not in ("visible", "hidden"):
        raise HTTPException(status_code=400, detail="status는 'visible' 또는 'hidden'만 가능합니다.")
    try:
        query = text("""
            UPDATE user_reports SET status = :status
            WHERE id = :id
            RETURNING id, status
        """)
        with engine.begin() as conn:
            row = conn.execute(query, {"status": new_status, "id": report_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="해당 제보를 찾을 수 없습니다.")
        return {"status": "success", "data": {"id": row[0], "report_status": row[1]}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"상태 변경 오류: {str(e)}")


@app.delete("/api/admin/reports/{report_id}")
def admin_delete_report(report_id: int, x_admin_key: Optional[str] = Header(None)):
    """제보 영구 삭제 (복구 불가). 스팸/악성 데이터 정리용."""
    require_admin(x_admin_key)
    try:
        query = text("DELETE FROM user_reports WHERE id = :id RETURNING id")
        with engine.begin() as conn:
            row = conn.execute(query, {"id": report_id}).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="해당 제보를 찾을 수 없습니다.")
        return {"status": "success", "data": {"id": row[0], "deleted": True}}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"삭제 오류: {str(e)}")