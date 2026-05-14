# RoadRunner

RoadRunner runs long-lived PHP workers. Avoid global request state, prefer PSR-7 request conversion, and ensure collectors remain stateless per request. Header order may be closer to runtime order, but still mark it with reliability metadata.