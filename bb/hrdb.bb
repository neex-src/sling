(ns hrdb
  "The HR database for the HRDB connector, in a podman container: Postgres 16 on 127.0.0.1:15432,
  database/user/password hr, schema and one row from test/fixtures/connectors/hrdb/schema.sql.
  Usage: bb hrdb:up | bb hrdb:down. up waits until it answers and is safe to run twice."
  (:require [babashka.process :refer [shell process]]
            [clojure.string :as str]))

(def container "sling-hrdb")

(defn- running? []
  (str/includes? (:out (shell {:out :string :continue true} "podman" "ps" "--format" "{{.Names}}")) container))

(defn- ready? []
  (zero? (:exit (shell {:out :string :err :string :continue true}
                       "podman" "exec" container "pg_isready" "-U" "hr" "-d" "hr"))))

(defn up []
  (when-not (running?)
    (shell "podman" "run" "-d" "--rm" "--name" container "-p" "127.0.0.1:15432:5432"
           "-e" "POSTGRES_USER=hr" "-e" "POSTGRES_PASSWORD=hr" "-e" "POSTGRES_DB=hr" "docker.io/library/postgres:16"))
  (loop [n 60] (when-not (ready?) (if (pos? n) (do (Thread/sleep 1000) (recur (dec n))) (throw (ex-info "hrdb did not start" {})))))
  (let [has-table (str/includes? (:out (shell {:out :string :continue true} "podman" "exec" container "psql" "-U" "hr" "-d" "hr" "-tc"
                                              "SELECT to_regclass('employees')")) "employees")]
    (when-not has-table
      (shell {:in (slurp "test/fixtures/connectors/hrdb/schema.sql")} "podman" "exec" "-i" container "psql" "-q" "-U" "hr" "-d" "hr")))
  (println "hrdb up: jdbc:postgresql://127.0.0.1:15432/hr (hr/hr)"))

(defn down [] (when (running?) (shell "podman" "stop" container)))

(case (first *command-line-args*) "down" (down) (up))
