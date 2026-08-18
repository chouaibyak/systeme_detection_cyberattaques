"""Acces Neo4j limite a la connexion, Cypher et au health check."""

import os
from typing import Any, Dict, Iterable, List, Optional


class Neo4jService:
    """Petit adaptateur synchrone, facilement remplacable dans les tests."""

    def __init__(self, uri=None, username=None, password=None, driver=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        self.username = username or os.getenv("NEO4J_USER", "neo4j")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self._driver = driver

    @property
    def driver(self):
        if self._driver is None:
            if not self.password:
                raise RuntimeError("NEO4J_PASSWORD est obligatoire pour se connecter a Neo4j")
            try:
                from neo4j import GraphDatabase
            except ImportError as error:
                raise RuntimeError("Le paquet neo4j est requis par investigation_layer") from error
            self._driver = GraphDatabase.driver(self.uri, auth=(self.username, self.password))
        return self._driver

    def run_write(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        with self.driver.session() as session:
            return session.execute_write(lambda tx: tx.run(query, parameters or {}).data())

    def run_read(self, query: str, parameters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        with self.driver.session() as session:
            return session.execute_read(lambda tx: tx.run(query, parameters or {}).data())

    def ensure_constraints(self, statements: Iterable[str]) -> None:
        for statement in statements:
            self.run_write(statement)

    def health_check(self) -> bool:
        try:
            return self.run_read("RETURN 1 AS ok")[0]["ok"] == 1
        except (IndexError, KeyError, RuntimeError):
            return False

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
            self._driver = None
