test: psql-up && psql-down
	logtalk_tester -p scryer -o verbose

test-scram: psql-up
	DATABASE_HOST=127.0.0.1 \
	DATABASE_PORT=5433 \
	DATABASE_USERNAME=postgres \
	DATABASE_PASSWORD=postgres \
	DATABASE_DB_NAME=postgres \
	scryer-prolog ./scram_test.pl -g 'run_test'

# First-argument indexing regression: expected to FAIL on v0.9.4
# (shift_* probes report solutions=[]). Override the binary with
# SCRYER_094=/path/to/scryer-prolog-0.9.4 if not on PATH.
test-indexing-v0_9_4:
	{{ env_var_or_default("SCRYER_094", "scryer-prolog-0.9.4") }} tests/indexing_regression.pl

# Expected to PASS on v0.10.0 (regression fixed upstream). Override
# with SCRYER_0100=/path/to/scryer-prolog if not on PATH.
test-indexing-v0_10_0:
	{{ env_var_or_default("SCRYER_0100", "scryer-prolog") }} tests/indexing_regression.pl

psql-up:
	docker-compose up -d postgres postgres-scram

psql-down:
	docker-compose down
