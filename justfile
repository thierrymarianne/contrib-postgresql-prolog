test: psql-up && psql-down
	logtalk_tester -p scryer -o verbose

test-scram: psql-up
	DATABASE_HOST=127.0.0.1 \
	DATABASE_PORT=5433 \
	DATABASE_USERNAME=postgres \
	DATABASE_PASSWORD=postgres \
	DATABASE_DB_NAME=postgres \
	scryer-prolog ./scram_test.pl -g 'run_test'

test-scram: psql-up
	scryer-prolog ./scram_test.pl -g 'run_test'

# Regression: SCRAM handshake must succeed when scryer's CWD is not
# this package root (the case every downstream submodule consumer
# hits). Runs from /tmp so any runtime relative `use_module(_)` in
# postgresql.pl is forced to resolve against a CWD with no package
# files in it.
test-scram-cwd-independence: psql-up
	REPO=$(pwd) && cd /tmp && \
	DATABASE_HOST=127.0.0.1 \
	DATABASE_PORT=5433 \
	DATABASE_USERNAME=postgres \
	DATABASE_PASSWORD=postgres \
	DATABASE_DB_NAME=postgres \
	scryer-prolog "$REPO/tests/scram_handshake_cwd_independence_test.pl" -g 'run_test'

psql-up:
	docker-compose up -d postgres postgres-scram

psql-down:
	docker-compose down
