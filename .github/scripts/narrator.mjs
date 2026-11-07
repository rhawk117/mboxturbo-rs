const failedJobResults = new Set([
  'failure',
  'cancelled',
  'timed_out',
  'action_required',
]);

const jobResultIcons = new Map([
  ['success', ':heavy_check_mark:'],
  ['failure', ':x:'],
  ['cancelled', ':no_entry:'],
  ['skipped', ':fast_forward:'],
  ['timed_out', ':warning:'],
  ['in_progress', ':hourglass:'],
  ['queued', ':hourglass:'],
]);

const statusLines = Object.freeze({
  empty: ':warning: No jobs found',
  pending: ':hourglass: Workflow in progress',
  failed: ':warning: One or more jobs failed',
  completed: ':heavy_check_mark: Reported jobs completed without failures',
});

class NarratorSettings {
  constructor(env) {
    this.title = env.NARRATOR_TITLE ?? 'CI Results';
    this.delimiter = env.NARRATOR_DELIMITER ?? '<!-- workflow-narrator:ci -->';
    this.jobName = env.NARRATOR_JOB_NAME ?? 'Workflow Narrator';
    this.branch = env.GITHUB_HEAD_REF || env.GITHUB_REF_NAME;
    this.runAttempt = Number(env.GITHUB_RUN_ATTEMPT);
  }
}

const jobResult = job => job.conclusion ?? job.status;

const formatDuration = ({ started_at, completed_at }) => {
  if (!started_at || !completed_at) {
    return '—';
  }

  const seconds = Math.round(
    (Date.parse(completed_at) - Date.parse(started_at)) / 1000,
  );
  return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
};

const formatJobRow = job => {
  const result = jobResult(job);
  const icon = jobResultIcons.get(result) ?? ':grey_question:';
  const title = result.charAt(0).toUpperCase() + result.slice(1);

  return `| ${job.name.replaceAll('|', '\\|')} | ${icon} ${title} | ${formatDuration(job)} | ${job.runner_name ?? '—'} | [View Job](${job.html_url}) |`;
};

const formatFailedSteps = job =>
  (job.steps ?? [])
    .filter(step => step.conclusion === 'failure')
    .map(step => `- **${job.name}:** ${step.name} ([logs](${job.html_url}))`);

const summarizeResults = jobs => {
  /** @type {Map<string, number>} */
  const resultCounts = new Map();
  for (const job of jobs) {
    resultCounts.set(
      jobResult(job),
      (resultCounts.get(jobResult(job)) ?? 0) + 1,
    );
  }

  return [...resultCounts]
    .map(([result, count]) => `${count} ${result}`)
    .join(' · ');
};

const narrationStatus = jobs => {
  if (jobs.length === 0) {
    return 'empty';
  }
  if (jobs.some(job => failedJobResults.has(job.conclusion))) {
    return 'failed';
  }
  if (jobs.some(job => job.status !== 'completed')) {
    return 'pending';
  }
  return 'completed';
};

const generateInitialSummary = (context, settings) => {
  const repositoryUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}`;
  const commit = context.payload.pull_request?.head.sha ?? context.sha;

  return [
    settings.delimiter,
    `## ${settings.title}`,
    '',
    `**${context.workflow}** · [Run #${context.runNumber}](${repositoryUrl}/actions/runs/${context.runId}) · Attempt ${settings.runAttempt}`,
    '',
    `**Branch:** \`${settings.branch}\``,
    `**Commit:** [\`${commit.slice(0, 7)}\`](${repositoryUrl}/commit/${commit})`,
    `**Triggered by:** @${context.actor} via \`${context.eventName}\``,
    '',
    '### Job Summary',
    '',
    '| Job | Result | Duration | Runner | Logs |',
    '| --- | --- | --- | --- | --- |',
  ];
};

const narrateJobHistory = (jobHistory, context, settings) => {
  const jobs = jobHistory.filter(job => job.name !== settings.jobName);
  const failedSteps = jobs.flatMap(formatFailedSteps);
  const failedStepSection = failedSteps.length
    ? ['', '### Failed Steps', '', ...failedSteps]
    : [];

  return [
    ...generateInitialSummary(context, settings),
    ...jobs.map(formatJobRow),
    '',
    `**${jobs.length} jobs:** ${summarizeResults(jobs) || 'none'}`,
    ...failedStepSection,
    '',
    statusLines[narrationStatus(jobs)],
  ].join('\n');
};

const collectJobInformation = ({ github, context }, settings) =>
  github.paginate(github.rest.actions.listJobsForWorkflowRunAttempt, {
    ...context.repo,
    run_id: context.runId,
    attempt_number: settings.runAttempt,
    per_page: 100,
  });

const upsertNarratorComment = async ({
  body,
  github,
  context,
  issueNumber,
  delimiter,
}) => {
  const comments = await github.paginate(github.rest.issues.listComments, {
    ...context.repo,
    issue_number: issueNumber,
    per_page: 100,
  });

  const existingComment = comments.find(
    comment =>
      comment.user?.login === 'github-actions[bot]' &&
      comment.body?.includes(delimiter),
  );

  if (existingComment) {
    await github.rest.issues.updateComment({
      ...context.repo,
      comment_id: existingComment.id,
      body,
    });
    return;
  }

  await github.rest.issues.createComment({
    ...context.repo,
    issue_number: issueNumber,
    body,
  });
};

const jobNarrator = async ({ github, context, core }, settings) => {
  const jobHistory = await collectJobInformation({ github, context }, settings);
  const narration = narrateJobHistory(jobHistory, context, settings);

  await core.summary.addRaw(narration, true).write();

  const pullRequest = context.payload.pull_request;
  if (context.eventName !== 'pull_request' || !pullRequest) {
    return;
  }

  const repository = `${context.repo.owner}/${context.repo.repo}`;
  if (pullRequest.head.repo?.full_name !== repository) {
    core.info('Skipping comment for fork pull request.');
    return;
  }

  await upsertNarratorComment({
    body: narration,
    github,
    context,
    issueNumber: pullRequest.number,
    delimiter: settings.delimiter,
  });
};

const narrate = async ({ github, context, core }) => {
  const settings = new NarratorSettings(process.env);
  await jobNarrator({ github, context, core }, settings).catch(error => {
    core.setFailed(`Failed to generate workflow narration: ${error}`);
  });
};

export default narrate;
