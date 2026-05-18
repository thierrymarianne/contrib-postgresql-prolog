test: psql-up && psql-down
	logtalk_tester -p scryer

test-scram: psql-up
	scryer-prolog ./scram_test.pl -g 'run_test'

psql-up:
	docker-compose up -d postgres

psql-down:
	docker-compose down
