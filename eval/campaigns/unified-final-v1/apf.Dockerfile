FROM slg-apf-apps:bd035dd06

USER root
COPY --chown=tester:tester eval/apps/demos /data/langgraph/eval/apps/demos
RUN install -d -o tester -g tester /data/langgraph/.argus-eval-results
USER tester
